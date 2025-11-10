/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Bottleneck Bandwidth and RTT (BBR) congestion control.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "bbr.c.clog.h"
#endif
#ifdef QUIC_ENHANCED_PACKET_LOGGING
#include "bbr_packet_level_logging.h"
#endif

typedef enum BBR_STATE {

    BBR_STATE_STARTUP,

    BBR_STATE_DRAIN,

    BBR_STATE_PROBE_BW,

    BBR_STATE_PROBE_RTT

} BBR_STATE;

typedef enum RECOVERY_STATE {

    RECOVERY_STATE_NOT_RECOVERY = 0,

    RECOVERY_STATE_CONSERVATIVE = 1,

    RECOVERY_STATE_GROWTH = 2,

} RECOVERY_STATE;

//
// Forward declarations
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlLogPacketSent(
    _In_ const QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t PacketSize
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
BbrCongestionControlGeneratePerformanceSummary(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    );

//
// Bandwidth is measured as (bytes / BW_UNIT) per second
//
#define BW_UNIT 8 // 1 << 3

//
// Gain is measured as (1 / GAIN_UNIT)
//
#define GAIN_UNIT 256 // 1 << 8

//
// The length of the gain cycle
//
#define GAIN_CYCLE_LENGTH 8

const uint64_t kQuantaFactor = 3;

const uint32_t kMinCwndInMss = 4;

const uint32_t kDefaultRecoveryCwndInMss = 2000;

const uint64_t kMicroSecsInSec = 1000000;

const uint64_t kMilliSecsInSec = 1000;

const uint64_t kLowPacingRateThresholdBytesPerSecond = 1200ULL * 1000;

const uint64_t kHighPacingRateThresholdBytesPerSecond = 24ULL * 1000 * 1000;

const uint32_t kHighGain = GAIN_UNIT * 2885 / 1000 + 1; // 2/ln(2)

const uint32_t kDrainGain = GAIN_UNIT * 1000 / 2885; // 1/kHighGain

//
// Cwnd gain during ProbeBw
//
const uint32_t kCwndGain = GAIN_UNIT * 2;

//
// The expected of bandwidth growth in each round trip time during STARTUP
//
const uint32_t kStartupGrowthTarget = GAIN_UNIT * 5 / 4;

//
// How many rounds of rtt to stay in STARTUP when the bandwidth isn't growing as
// fast as kStartupGrowthTarget
//
const uint8_t kStartupSlowGrowRoundLimit = 3;

//
// The cycle of gains used during the PROBE_BW stage
//
const uint32_t kPacingGain[GAIN_CYCLE_LENGTH] = {
    GAIN_UNIT * 5 / 4,
    GAIN_UNIT * 3 / 4,
    GAIN_UNIT, GAIN_UNIT, GAIN_UNIT,
    GAIN_UNIT, GAIN_UNIT, GAIN_UNIT
};

//
// During ProbeRtt, we need to stay in low inflight condition for at least kProbeRttTimeInUs
//
const uint32_t kProbeRttTimeInUs = 200 * 1000;

//
// Time until a MinRtt measurement is expired.
//
const uint32_t kBbrMinRttExpirationInMicroSecs = S_TO_US(10);

const uint32_t kBbrMaxBandwidthFilterLen = 10;

const uint32_t kBbrMaxAckHeightFilterLen = 10;

#ifdef QUIC_ENHANCED_PACKET_LOGGING
//
// Global BBR packet level logger
//
static BBR_PACKET_LOGGER g_BbrPacketLogger = { 0 };
static BOOLEAN g_BbrPacketLoggerInitialized = FALSE;
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrBandwidthFilterOnPacketAcked(
    _In_ BBR_BANDWIDTH_FILTER* b,
    _In_ const QUIC_ACK_EVENT* AckEvent,
    _In_ uint64_t RttCounter
    )
{
    if (b->AppLimited && b->AppLimitedExitTarget < AckEvent->LargestAck) {
        b->AppLimited = FALSE;
    }

    uint64_t TimeNow = AckEvent->TimeNow;

    QUIC_SENT_PACKET_METADATA* AckedPacketsIterator = AckEvent->AckedPackets;
    while (AckedPacketsIterator != NULL) {
        QUIC_SENT_PACKET_METADATA* AckedPacket = AckedPacketsIterator;
        AckedPacketsIterator = AckedPacketsIterator->Next;

        if (AckedPacket->PacketLength == 0) {
            continue;
        }

        uint64_t SendRate = UINT64_MAX;
        uint64_t AckRate = UINT64_MAX;
        uint64_t SendElapsed = 0;  // Declare outside of if block for later use
        uint64_t AckElapsed = 0;   // Declare outside of if block for later use

        if (AckedPacket->Flags.HasLastAckedPacketInfo) {
            CXPLAT_DBG_ASSERT(AckedPacket->TotalBytesSent >= AckedPacket->LastAckedPacketInfo.TotalBytesSent);
            CXPLAT_DBG_ASSERT(CxPlatTimeAtOrBefore64(AckedPacket->LastAckedPacketInfo.SentTime, AckedPacket->SentTime));

            SendElapsed = CxPlatTimeDiff64(AckedPacket->LastAckedPacketInfo.SentTime, AckedPacket->SentTime);

            if (SendElapsed) {
                SendRate = (kMicroSecsInSec * BW_UNIT *
                    (AckedPacket->TotalBytesSent - AckedPacket->LastAckedPacketInfo.TotalBytesSent) /
                    SendElapsed);
            }

            if (!CxPlatTimeAtOrBefore64(AckEvent->AdjustedAckTime, AckedPacket->LastAckedPacketInfo.AdjustedAckTime)) {
                AckElapsed = CxPlatTimeDiff64(AckedPacket->LastAckedPacketInfo.AdjustedAckTime, AckEvent->AdjustedAckTime);
            } else {
                AckElapsed = CxPlatTimeDiff64(AckedPacket->LastAckedPacketInfo.AckTime, TimeNow);
            }

            CXPLAT_DBG_ASSERT(AckEvent->NumTotalAckedRetransmittableBytes >= AckedPacket->LastAckedPacketInfo.TotalBytesAcked);
            if (AckElapsed) {
                AckRate = (kMicroSecsInSec * BW_UNIT *
                           (AckEvent->NumTotalAckedRetransmittableBytes - AckedPacket->LastAckedPacketInfo.TotalBytesAcked) /
                           AckElapsed);
            }
        } else if (!CxPlatTimeAtOrBefore64(TimeNow, AckedPacket->SentTime)) {
            CXPLAT_DBG_ASSERT(CxPlatTimeDiff64(AckedPacket->SentTime, TimeNow) != 0);
            SendRate = (kMicroSecsInSec * BW_UNIT *
                        AckEvent->NumTotalAckedRetransmittableBytes /
                        CxPlatTimeDiff64(AckedPacket->SentTime, TimeNow));
        }

        if (SendRate == UINT64_MAX && AckRate == UINT64_MAX) {
            continue;
        }

        uint64_t DeliveryRate = CXPLAT_MIN(SendRate, AckRate);

        QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = (QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY) { .Value = 0, .Time = 0 };
        QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&b->WindowedMaxFilter, &Entry);

        uint64_t PreviousMaxDeliveryRate = 0;
        if (QUIC_SUCCEEDED(Status)) {
            PreviousMaxDeliveryRate = Entry.Value;
        }

        if (DeliveryRate >= PreviousMaxDeliveryRate || !AckedPacket->Flags.IsAppLimited) {
            QuicSlidingWindowExtremumUpdateMax(&b->WindowedMaxFilter, DeliveryRate, RttCounter);
        }

        // TODO: Add delay tracking here later when CLOG issues are resolved
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
BbrCongestionControlGetBandwidth(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = (QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY) { .Value = 0, .Time = 0 };
    QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Cc->Bbr.BandwidthFilter.WindowedMaxFilter, &Entry);
    if (QUIC_SUCCEEDED(Status)) {
        return Entry.Value;
    }
    return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlInRecovery(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
)
{
    return Cc->Bbr.RecoveryState != RECOVERY_STATE_NOT_RECOVERY;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrCongestionControlGetCongestionWindow(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    const QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    uint32_t MinCongestionWindow = kMinCwndInMss * DatagramPayloadLength;

    if (Bbr->BbrState == BBR_STATE_PROBE_RTT) {
        return MinCongestionWindow;
    }

    if (BbrCongestionControlInRecovery(Cc)) {
        return CXPLAT_MIN(Bbr->CongestionWindow, Bbr->RecoveryWindow);
    }

    return Bbr->CongestionWindow;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToProbeBw(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t CongestionEventTime
    )
{
    QUIC_CONGESTION_CONTROL_BBR *Bbr = &Cc->Bbr;

    Bbr->BbrState = BBR_STATE_PROBE_BW;
    Bbr->CwndGain = kCwndGain;

    uint32_t RandomValue = 0;
    CxPlatRandom(sizeof(uint32_t), &RandomValue);
    Bbr->PacingCycleIndex = (RandomValue % (GAIN_CYCLE_LENGTH - 1) + 2) % GAIN_CYCLE_LENGTH;
    CXPLAT_DBG_ASSERT(Bbr->PacingCycleIndex != 1);
    Bbr->PacingGain = kPacingGain[Bbr->PacingCycleIndex];

    Bbr->CycleStart = CongestionEventTime;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToStartup(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->Bbr.BbrState = BBR_STATE_STARTUP;
    Cc->Bbr.PacingGain = kHighGain;
    Cc->Bbr.CwndGain = kHighGain;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlIsAppLimited(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr.BandwidthFilter.AppLimited;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnLogBbr(
    _In_ QUIC_CONNECTION* const Connection
    )
{
    QUIC_CONGESTION_CONTROL* Cc = &Connection->CongestionControl;
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    QuicTraceEvent(
        ConnBbr,
        "[conn][%p] BBR: State=%u RState=%u CongestionWindow=%u BytesInFlight=%u BytesInFlightMax=%u MinRttEst=%lu EstBw=%lu AppLimited=%u",
        Connection,
        Bbr->BbrState,
        Bbr->RecoveryState,
        BbrCongestionControlGetCongestionWindow(Cc),
        Bbr->BytesInFlight,
        Bbr->BytesInFlightMax,
        Bbr->MinRtt,
        BbrCongestionControlGetBandwidth(Cc) / BW_UNIT,
        BbrCongestionControlIsAppLimited(Cc));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlIndicateConnectionEvent(
    _In_ QUIC_CONNECTION* const Connection,
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    const QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    const QUIC_PATH* Path = &Connection->Paths[0];
    QUIC_CONNECTION_EVENT Event;
    Event.Type = QUIC_CONNECTION_EVENT_NETWORK_STATISTICS;
    Event.NETWORK_STATISTICS.BytesInFlight = Bbr->BytesInFlight;
    Event.NETWORK_STATISTICS.PostedBytes = Connection->SendBuffer.PostedBytes;
    Event.NETWORK_STATISTICS.IdealBytes = Connection->SendBuffer.IdealBytes;
    Event.NETWORK_STATISTICS.SmoothedRTT = Path->SmoothedRtt;
    Event.NETWORK_STATISTICS.CongestionWindow = BbrCongestionControlGetCongestionWindow(Cc);
    Event.NETWORK_STATISTICS.Bandwidth = BbrCongestionControlGetBandwidth(Cc) / BW_UNIT;

    QuicTraceLogConnVerbose(
        IndicateDataAcked,
        Connection,
        "Indicating QUIC_CONNECTION_EVENT_NETWORK_STATISTICS [BytesInFlight=%u,PostedBytes=%llu,IdealBytes=%llu,SmoothedRTT=%llu,CongestionWindow=%u,Bandwidth=%llu]",
        Event.NETWORK_STATISTICS.BytesInFlight,
        Event.NETWORK_STATISTICS.PostedBytes,
        Event.NETWORK_STATISTICS.IdealBytes,
        Event.NETWORK_STATISTICS.SmoothedRTT,
        Event.NETWORK_STATISTICS.CongestionWindow,
        Event.NETWORK_STATISTICS.Bandwidth);
    QuicConnIndicateEvent(Connection, &Event);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlCanSend(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    uint32_t CongestionWindow = BbrCongestionControlGetCongestionWindow(Cc);
    return Cc->Bbr.BytesInFlight < CongestionWindow || Cc->Bbr.Exemptions > 0;
}

void
BbrCongestionControlLogOutFlowStatus(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    const QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    const QUIC_PATH* Path = &Connection->Paths[0];
    const QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    QuicTraceEvent(
        ConnOutFlowStatsV2,
        "[conn][%p] OUT: BytesSent=%llu InFlight=%u CWnd=%u ConnFC=%llu ISB=%llu PostedBytes=%llu SRtt=%llu 1Way=%llu",
        Connection,
        Connection->Stats.Send.TotalBytes,
        Bbr->BytesInFlight,
        Bbr->CongestionWindow,
        Connection->Send.PeerMaxData - Connection->Send.OrderedStreamBytesSent,
        Connection->SendBuffer.IdealBytes,
        Connection->SendBuffer.PostedBytes,
        Path->GotFirstRttSample ? Path->SmoothedRtt : 0,
        Path->OneWayDelay);
}

//
// Returns TRUE if we became unblocked.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlUpdateBlockedState(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN PreviousCanSendState
    )
{
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    QuicConnLogOutFlowStats(Connection);

    if (PreviousCanSendState != BbrCongestionControlCanSend(Cc)) {
        if (PreviousCanSendState) {
            QuicConnAddOutFlowBlockedReason(
                Connection, QUIC_FLOW_BLOCKED_CONGESTION_CONTROL);
        } else {
            QuicConnRemoveOutFlowBlockedReason(
                Connection, QUIC_FLOW_BLOCKED_CONGESTION_CONTROL);
            Connection->Send.LastFlushTime = CxPlatTimeUs64(); // Reset last flush time
            return TRUE;
        }
    }
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrCongestionControlGetBytesInFlightMax(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr.BytesInFlightMax;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint8_t
BbrCongestionControlGetExemptions(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr.Exemptions;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlSetExemption(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint8_t NumPackets
    )
{
    Cc->Bbr.Exemptions = NumPackets;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlOnDataSent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    BOOLEAN PreviousCanSendState = BbrCongestionControlCanSend(Cc);

    if (!Bbr->BytesInFlight && BbrCongestionControlIsAppLimited(Cc)) {
        Bbr->ExitingQuiescence = TRUE;
    }



    Bbr->BytesInFlight += NumRetransmittableBytes;
    if (Bbr->BytesInFlightMax < Bbr->BytesInFlight) {
        Bbr->BytesInFlightMax = Bbr->BytesInFlight;
        QuicSendBufferConnectionAdjust(QuicCongestionControlGetConnection(Cc));
    }

    if (Bbr->Exemptions > 0) {
        --Bbr->Exemptions;
    }

    // Log BBR state for each packet transmission
     BbrCongestionControlLogPacketSent(Cc, NumRetransmittableBytes);

#ifdef QUIC_ENHANCED_PACKET_LOGGING
    // Enhanced packet level logging
    if (g_BbrPacketLoggerInitialized) {
        QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
        uint64_t PacketNumber = Connection->LossDetection.LargestSentPacketNumber + 1;
        BbrPacketLevelLoggingRecordPacketSent(&g_BbrPacketLogger, Cc, PacketNumber, NumRetransmittableBytes);
    }
#endif

    BbrCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlLogPacketSent(
    _In_ const QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t PacketSize
    )
{
    const QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    const QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    const QUIC_PATH* Path = &Connection->Paths[0];
    
    uint64_t EstimatedBandwidth = BbrCongestionControlGetBandwidth(Cc);
    uint32_t CongestionWindow = BbrCongestionControlGetCongestionWindow(Cc);
    uint64_t SmoothedRtt = Path->GotFirstRttSample ? Path->SmoothedRtt : 0;
    uint64_t MinRtt = Bbr->MinRtt != UINT64_MAX ? Bbr->MinRtt : 0;
    uint32_t BytesInFlight = Bbr->BytesInFlight;
    uint64_t TotalPacketsSent = Connection->Stats.Send.TotalPackets;
    uint64_t TotalPacketsLost = Connection->Stats.Send.SuspectedLostPackets;
    double LossRate = TotalPacketsSent > 0 ? ((double)TotalPacketsLost * 100.0) / (double)TotalPacketsSent : 0.0;

    // Calculate pacing rate and delivery rate
    uint64_t PacingRate = EstimatedBandwidth * Bbr->PacingGain / GAIN_UNIT;
    uint64_t DeliveryRate = Bbr->RecentDeliveryRate;
    
    // Calculate connection duration
    uint64_t CurrentTime = CxPlatTimeUs64();
    uint64_t ConnectionDuration = CurrentTime - Connection->Stats.Timing.Start;
    
    // Write detailed BBR packet log to the same log file as periodic logs
    FILE* logFile = fopen("bbr_logs/quicbbr.txt", "a");
    if (logFile != NULL) {
        fprintf(logFile, "[BBR-PKT-SENT] T=%lu.%03lu s, PKT=%lu, Size=%u B, "
               "EstBW=%.2f Mbps, PacingRate=%.2f Mbps, DeliveryRate=%.2f Mbps, "
               "RTT=%lu us, MinRTT=%lu us, CWND=%u B, InFlight=%u B, "
               "Loss=%.2f%%, State=%s, TotalSent=%lu, TotalLost=%lu, "
               "SendDelay=%lu us, AckDelay=%lu us, PacingGain=%.2fx, CwndGain=%.2fx\n",
               (unsigned long)(ConnectionDuration / 1000000),
               (unsigned long)((ConnectionDuration % 1000000) / 1000),
               (unsigned long)TotalPacketsSent,
               PacketSize,
               EstimatedBandwidth / 1000000.0,
               PacingRate / 1000000.0,
               DeliveryRate / 1000000.0,
               (unsigned long)SmoothedRtt,
               (unsigned long)MinRtt,
               CongestionWindow,
               BytesInFlight,
               LossRate,
               Bbr->BbrState == 0 ? "STARTUP" :
               Bbr->BbrState == 1 ? "DRAIN" :
               Bbr->BbrState == 2 ? "PROBE_BW" :
               Bbr->BbrState == 3 ? "PROBE_RTT" : "UNKNOWN",
               (unsigned long)TotalPacketsSent,
               (unsigned long)TotalPacketsLost,
               (unsigned long)Bbr->RecentSendDelay,
               (unsigned long)Bbr->RecentAckDelay,
               (double)Bbr->PacingGain / (double)GAIN_UNIT,  // Added PacingGain
               (double)Bbr->CwndGain / (double)GAIN_UNIT);   // Added CwndGain
        fclose(logFile);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlOnDataInvalidated(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    BOOLEAN PreviousCanSendState = BbrCongestionControlCanSend(Cc);

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= NumRetransmittableBytes);
    Bbr->BytesInFlight -= NumRetransmittableBytes;

    return BbrCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlUpdateRecoveryWindow(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t BytesAcked
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    CXPLAT_DBG_ASSERT(Bbr->RecoveryState != RECOVERY_STATE_NOT_RECOVERY);

    if (Bbr->RecoveryState == RECOVERY_STATE_GROWTH) {
        Bbr->RecoveryWindow += BytesAcked;
    }

    uint32_t RecoveryWindow = CXPLAT_MAX(
        Bbr->RecoveryWindow, Bbr->BytesInFlight + BytesAcked);

    uint32_t MinCongestionWindow = kMinCwndInMss * DatagramPayloadLength;

    Bbr->RecoveryWindow = CXPLAT_MAX(RecoveryWindow, MinCongestionWindow);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlHandleAckInProbeRtt(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN NewRoundTrip,
    _In_ uint64_t LargestSentPacketNumber,
    _In_ uint64_t AckTime
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    Bbr->BandwidthFilter.AppLimited = TRUE;
    Bbr->BandwidthFilter.AppLimitedExitTarget = LargestSentPacketNumber;

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    if (!Bbr->ProbeRttEndTimeValid &&
        Bbr->BytesInFlight < BbrCongestionControlGetCongestionWindow(Cc) + DatagramPayloadLength) {

        Bbr->ProbeRttEndTime = AckTime + kProbeRttTimeInUs;
        Bbr->ProbeRttEndTimeValid = TRUE;

        Bbr->ProbeRttRoundValid = FALSE;

        return;
    }

    if (Bbr->ProbeRttEndTimeValid) {

        if (!Bbr->ProbeRttRoundValid && NewRoundTrip) {
            Bbr->ProbeRttRoundValid = TRUE;
            Bbr->ProbeRttRound = Bbr->RoundTripCounter;
        }

        if (Bbr->ProbeRttRoundValid && CxPlatTimeAtOrBefore64(Bbr->ProbeRttEndTime, AckTime)) {
            Bbr->MinRttTimestamp = AckTime;
            Bbr->MinRttTimestampValid = TRUE;

            if (Bbr->BtlbwFound) {
                BbrCongestionControlTransitToProbeBw(Cc, AckTime);
            } else {
                BbrCongestionControlTransitToStartup(Cc);
            }
        }

    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
BbrCongestionControlUpdateAckAggregation(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ACK_EVENT* AckEvent
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    if (!Bbr->AckAggregationStartTimeValid) {
        Bbr->AckAggregationStartTime = AckEvent->TimeNow;
        Bbr->AckAggregationStartTimeValid = TRUE;
        return 0;
    }

    uint64_t ExpectedAckBytes = BbrCongestionControlGetBandwidth(Cc) *
                                CxPlatTimeDiff64(Bbr->AckAggregationStartTime, AckEvent->TimeNow) /
                                kMicroSecsInSec /
                                BW_UNIT;

    //
    // Reset current ack aggregation status when we witness ack arrival rate being less or equal than
    // estimated bandwidth
    //
    if (Bbr->AggregatedAckBytes <= ExpectedAckBytes) {
        Bbr->AggregatedAckBytes = AckEvent->NumRetransmittableBytes;
        Bbr->AckAggregationStartTime = AckEvent->TimeNow;
        Bbr->AckAggregationStartTimeValid = TRUE;

        return 0;
    }

    Bbr->AggregatedAckBytes += AckEvent->NumRetransmittableBytes;

    QuicSlidingWindowExtremumUpdateMax(&Bbr->MaxAckHeightFilter,
        Bbr->AggregatedAckBytes - ExpectedAckBytes, Bbr->RoundTripCounter);

    return Bbr->AggregatedAckBytes - ExpectedAckBytes;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrCongestionControlGetTargetCwnd(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t Gain
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    uint64_t BandwidthEst = BbrCongestionControlGetBandwidth(Cc);

    if (!BandwidthEst || Bbr->MinRtt == UINT32_MAX) {
        return (uint64_t)(Gain) * Bbr->InitialCongestionWindow / GAIN_UNIT;
    }

    uint64_t Bdp = BandwidthEst * Bbr->MinRtt / kMicroSecsInSec / BW_UNIT;
    uint64_t TargetCwnd = (Bdp * Gain / GAIN_UNIT) + (kQuantaFactor * Bbr->SendQuantum);
    return (uint32_t)TargetCwnd;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrCongestionControlGetSendAllowance(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeSinceLastSend, // microsec
    _In_ BOOLEAN TimeSinceLastSendValid
    )
{
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    uint64_t BandwidthEst = BbrCongestionControlGetBandwidth(Cc);
    uint32_t CongestionWindow = BbrCongestionControlGetCongestionWindow(Cc);

    uint32_t SendAllowance = 0;

    if (Bbr->BytesInFlight >= CongestionWindow) {
        //
        // We are CC blocked, so we can't send anything.
        //
        SendAllowance = 0;

    } else if (
        !TimeSinceLastSendValid ||
        !Connection->Settings.PacingEnabled ||
        Bbr->MinRtt == UINT32_MAX ||
        Bbr->MinRtt < QUIC_SEND_PACING_INTERVAL) {
        //
        // We're not in the necessary state to pace.
        //
        SendAllowance = CongestionWindow - Bbr->BytesInFlight;

    } else {
        //
        // We are pacing, so split the congestion window into chunks which are
        // spread out over the RTT. Calculate the current send allowance (chunk
        // size) as the time since the last send times the pacing rate (CWND / RTT).
        //
        if (Bbr->BbrState == BBR_STATE_STARTUP) {
            SendAllowance = (uint32_t)CXPLAT_MAX(
                BandwidthEst * Bbr->PacingGain * TimeSinceLastSend / GAIN_UNIT,
                CongestionWindow * Bbr->PacingGain / GAIN_UNIT - Bbr->BytesInFlight);
        } else {
            SendAllowance = (uint32_t)(BandwidthEst * Bbr->PacingGain * TimeSinceLastSend / GAIN_UNIT);
        }

        if (SendAllowance > CongestionWindow - Bbr->BytesInFlight) {
            SendAllowance = CongestionWindow - Bbr->BytesInFlight;
        }

        if (SendAllowance > (CongestionWindow >> 2)) {
            SendAllowance = CongestionWindow >> 2; // Don't send more than a quarter of the current window.
        }
    }
    return SendAllowance;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToProbeRtt(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t LargestSentPacketNumber
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    Bbr->BbrState = BBR_STATE_PROBE_RTT;
    Bbr->PacingGain = GAIN_UNIT;
    Bbr->ProbeRttEndTimeValid = FALSE;
    Bbr->ProbeRttRoundValid = FALSE;

    Bbr->BandwidthFilter.AppLimited = TRUE;
    Bbr->BandwidthFilter.AppLimitedExitTarget = LargestSentPacketNumber;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToDrain(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->Bbr.BbrState = BBR_STATE_DRAIN;
    Cc->Bbr.PacingGain = kDrainGain;
    Cc->Bbr.CwndGain = kHighGain;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlSetSendQuantum(
    _In_ QUIC_CONGESTION_CONTROL* Cc
)
{
    QUIC_CONGESTION_CONTROL_BBR *Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    uint64_t Bandwidth = BbrCongestionControlGetBandwidth(Cc);

    uint64_t PacingRate = Bandwidth * Bbr->PacingGain / GAIN_UNIT;

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    if (PacingRate < kLowPacingRateThresholdBytesPerSecond * BW_UNIT) {
        Bbr->SendQuantum = (uint64_t)DatagramPayloadLength;
    } else if (PacingRate < kHighPacingRateThresholdBytesPerSecond * BW_UNIT) {
        Bbr->SendQuantum = (uint64_t)DatagramPayloadLength * 2;
    } else {
        Bbr->SendQuantum = CXPLAT_MIN(PacingRate * kMilliSecsInSec / BW_UNIT, 64 * 1024 /* 64k */);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlUpdateCongestionWindow(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TotalBytesAcked,
    _In_ uint64_t AckedBytes
    )
{
    QUIC_CONGESTION_CONTROL_BBR *Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    if (Bbr->BbrState == BBR_STATE_PROBE_RTT) {
        return;
    }

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    BbrCongestionControlSetSendQuantum(Cc);

    uint64_t TargetCwnd = BbrCongestionControlGetTargetCwnd(Cc, Bbr->CwndGain);
    if (Bbr->BtlbwFound) {
        QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = (QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY) { .Value = 0, .Time = 0 };
        QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Bbr->MaxAckHeightFilter, &Entry);
        if (QUIC_SUCCEEDED(Status)) {
            TargetCwnd += Entry.Value;
        }
    }

    uint32_t CongestionWindow = Bbr->CongestionWindow;
    uint32_t MinCongestionWindow = kMinCwndInMss * DatagramPayloadLength;

    if (Bbr->BtlbwFound) {
        CongestionWindow = (uint32_t)CXPLAT_MIN(TargetCwnd, CongestionWindow + AckedBytes);
    } else if (CongestionWindow < TargetCwnd || TotalBytesAcked < Bbr->InitialCongestionWindow) {
        CongestionWindow += (uint32_t)AckedBytes;
    }

    Bbr->CongestionWindow = CXPLAT_MAX(CongestionWindow, MinCongestionWindow);

    QuicConnLogBbr(QuicCongestionControlGetConnection(Cc));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlOnDataAcknowledged(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ACK_EVENT* AckEvent
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    BOOLEAN PreviousCanSendState = BbrCongestionControlCanSend(Cc);
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    if (AckEvent->IsImplicit) {
        BbrCongestionControlUpdateCongestionWindow(
            Cc, AckEvent->NumTotalAckedRetransmittableBytes, AckEvent->NumRetransmittableBytes);

        if (Connection->Settings.NetStatsEventEnabled) {
            BbrCongestionControlIndicateConnectionEvent(Connection, Cc);
        }
        return BbrCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
    }

    uint32_t PrevInflightBytes = Bbr->BytesInFlight;

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= AckEvent->NumRetransmittableBytes);
    Bbr->BytesInFlight -= AckEvent->NumRetransmittableBytes;

    if (AckEvent->MinRttValid) {
        Bbr->RttSampleExpired = Bbr->MinRttTimestampValid ?
           CxPlatTimeAtOrBefore64(Bbr->MinRttTimestamp + kBbrMinRttExpirationInMicroSecs, AckEvent->TimeNow) :
           FALSE;
        if (Bbr->RttSampleExpired || Bbr->MinRtt > AckEvent->MinRtt) {
            Bbr->MinRtt = AckEvent->MinRtt;
            Bbr->MinRttTimestamp = AckEvent->TimeNow;
            Bbr->MinRttTimestampValid = TRUE;
        }
    }

    BOOLEAN NewRoundTrip = FALSE;
    if (!Bbr->EndOfRoundTripValid || Bbr->EndOfRoundTrip < AckEvent->LargestAck) {
        Bbr->RoundTripCounter++;
        Bbr->EndOfRoundTripValid = TRUE;
        Bbr->EndOfRoundTrip = AckEvent->LargestSentPacketNumber;
        NewRoundTrip = TRUE;
    }

    BOOLEAN LastAckedPacketAppLimited =
        AckEvent->AckedPackets == NULL ? FALSE : AckEvent->IsLargestAckedPacketAppLimited;

    BbrBandwidthFilterOnPacketAcked(&Bbr->BandwidthFilter, AckEvent, Bbr->RoundTripCounter);

    // Update recent delivery rate tracking for logging
    // Calculate delivery rate based on recent ACK events
    QUIC_SENT_PACKET_METADATA* AckedPacketsIterator = AckEvent->AckedPackets;
    while (AckedPacketsIterator != NULL) {
        QUIC_SENT_PACKET_METADATA* AckedPacket = AckedPacketsIterator;
        AckedPacketsIterator = AckedPacketsIterator->Next;

        if (AckedPacket->PacketLength == 0) {
            continue;
        }

        uint64_t SendRate = UINT64_MAX;
        uint64_t AckRate = UINT64_MAX;
        uint64_t TimeNow = AckEvent->TimeNow;

        if (AckedPacket->Flags.HasLastAckedPacketInfo) {
            uint64_t SendElapsed = CxPlatTimeDiff64(AckedPacket->LastAckedPacketInfo.SentTime, AckedPacket->SentTime);
            if (SendElapsed) {
                SendRate = (kMicroSecsInSec * BW_UNIT *
                    (AckedPacket->TotalBytesSent - AckedPacket->LastAckedPacketInfo.TotalBytesSent) /
                    SendElapsed);
                // Record the actual send delay used in delivery rate calculation
                Bbr->RecentSendDelay = SendElapsed;
            }

            uint64_t AckElapsed = 0;
            if (!CxPlatTimeAtOrBefore64(AckEvent->AdjustedAckTime, AckedPacket->LastAckedPacketInfo.AdjustedAckTime)) {
                AckElapsed = CxPlatTimeDiff64(AckedPacket->LastAckedPacketInfo.AdjustedAckTime, AckEvent->AdjustedAckTime);
            } else {
                AckElapsed = CxPlatTimeDiff64(AckedPacket->LastAckedPacketInfo.AckTime, TimeNow);
            }

            if (AckElapsed) {
                AckRate = (kMicroSecsInSec * BW_UNIT *
                           (AckEvent->NumTotalAckedRetransmittableBytes - AckedPacket->LastAckedPacketInfo.TotalBytesAcked) /
                           AckElapsed);
                // Record the actual ack delay used in delivery rate calculation
                Bbr->RecentAckDelay = AckElapsed;
            }
        } else if (!CxPlatTimeAtOrBefore64(TimeNow, AckedPacket->SentTime)) {
            uint64_t RttElapsed = CxPlatTimeDiff64(AckedPacket->SentTime, TimeNow);
            SendRate = (kMicroSecsInSec * BW_UNIT *
                        AckEvent->NumTotalAckedRetransmittableBytes /
                        RttElapsed);
            // Record RTT-based delay when no previous packet info available
            Bbr->RecentSendDelay = RttElapsed;
            Bbr->RecentAckDelay = RttElapsed;
        }

        if (SendRate != UINT64_MAX || AckRate != UINT64_MAX) {
            uint64_t DeliveryRate = CXPLAT_MIN(SendRate, AckRate);
            if (DeliveryRate != UINT64_MAX) {
                Bbr->RecentSendRate = SendRate;
                Bbr->RecentAckRate = AckRate;
                Bbr->RecentDeliveryRate = DeliveryRate;
                

                
                break; // Use the first valid delivery rate
            }
        }
    }

    if (BbrCongestionControlInRecovery(Cc)) {
        CXPLAT_DBG_ASSERT(Bbr->EndOfRecoveryValid);
        if (NewRoundTrip && Bbr->RecoveryState != RECOVERY_STATE_GROWTH) {
            Bbr->RecoveryState = RECOVERY_STATE_GROWTH;
        }
        if (!AckEvent->HasLoss && Bbr->EndOfRecovery < AckEvent->LargestAck) {
            Bbr->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
            QuicTraceEvent(
                ConnRecoveryExit,
                "[conn][%p] Recovery complete",
                Connection);
        } else {
            BbrCongestionControlUpdateRecoveryWindow(Cc, AckEvent->NumRetransmittableBytes);
        }
    }

    BbrCongestionControlUpdateAckAggregation(Cc, AckEvent);

    if (Bbr->BbrState == BBR_STATE_PROBE_BW) {
        BOOLEAN ShouldAdvancePacingGainCycle = CxPlatTimeDiff64(AckEvent->TimeNow, Bbr->CycleStart) > Bbr->MinRtt;

        if (Bbr->PacingGain > GAIN_UNIT && !AckEvent->HasLoss &&
            PrevInflightBytes < BbrCongestionControlGetTargetCwnd(Cc, Bbr->PacingGain)) {
            ShouldAdvancePacingGainCycle = FALSE;
        }

        if (Bbr->PacingGain < GAIN_UNIT) {
            uint64_t TargetCwnd = BbrCongestionControlGetTargetCwnd(Cc, GAIN_UNIT);
            if (Bbr->BytesInFlight <= TargetCwnd) {
                ShouldAdvancePacingGainCycle = TRUE;
            }
        }

        if (ShouldAdvancePacingGainCycle) {
            Bbr->PacingCycleIndex = (Bbr->PacingCycleIndex + 1) % GAIN_CYCLE_LENGTH;
            Bbr->CycleStart = AckEvent->TimeNow;
            Bbr->PacingGain = kPacingGain[Bbr->PacingCycleIndex];
        }
    }

    if (!Bbr->BtlbwFound && NewRoundTrip && !LastAckedPacketAppLimited) {
        uint64_t BandwidthTarget = (uint64_t)(Bbr->LastEstimatedStartupBandwidth * kStartupGrowthTarget / GAIN_UNIT);
        uint64_t CurrentBandwidth = BbrCongestionControlGetBandwidth(Cc);

        if (CurrentBandwidth >= BandwidthTarget) {
            Bbr->LastEstimatedStartupBandwidth = CurrentBandwidth;
            Bbr->SlowStartupRoundCounter = 0;
        } else if (++Bbr->SlowStartupRoundCounter >= kStartupSlowGrowRoundLimit) {
            Bbr->BtlbwFound = TRUE;
        }
    }

    if (Bbr->BbrState == BBR_STATE_STARTUP && Bbr->BtlbwFound) {
        BbrCongestionControlTransitToDrain(Cc);
    }

    if (Bbr->BbrState == BBR_STATE_DRAIN &&
           Bbr->BytesInFlight <= BbrCongestionControlGetTargetCwnd(Cc, GAIN_UNIT)) {
        BbrCongestionControlTransitToProbeBw(Cc, AckEvent->TimeNow);
    }

    if (Bbr->BbrState != BBR_STATE_PROBE_RTT &&
        !Bbr->ExitingQuiescence &&
        Bbr->RttSampleExpired) {
        BbrCongestionControlTransitToProbeRtt(Cc, AckEvent->LargestSentPacketNumber);
    }

    Bbr->ExitingQuiescence = FALSE;

    if (Bbr->BbrState == BBR_STATE_PROBE_RTT) {
        BbrCongestionControlHandleAckInProbeRtt(
            Cc, NewRoundTrip, AckEvent->LargestSentPacketNumber, AckEvent->TimeNow);
    }

    BbrCongestionControlUpdateCongestionWindow(
        Cc, AckEvent->NumTotalAckedRetransmittableBytes, AckEvent->NumRetransmittableBytes);

    // Log each acknowledged packet (disabled for periodic logging)
    if (AckEvent->AckedPackets != NULL) {
        const QUIC_PATH* Path = &Connection->Paths[0];
        QUIC_SENT_PACKET_METADATA* AckedPacket = AckEvent->AckedPackets;
        while (AckedPacket != NULL) {
            // Calculate BBR metrics for this ACK event
            uint64_t EstimatedBandwidth = BbrCongestionControlGetBandwidth(Cc);
            uint32_t CongestionWindow = BbrCongestionControlGetCongestionWindow(Cc);
            uint64_t SmoothedRtt = Path->GotFirstRttSample ? Path->SmoothedRtt : 0;
            uint64_t MinRtt = Bbr->MinRtt != UINT64_MAX ? Bbr->MinRtt : 0;
            uint64_t PacingRate = EstimatedBandwidth * Bbr->PacingGain / GAIN_UNIT;
            uint64_t DeliveryRate = Bbr->RecentDeliveryRate;
            
            // Calculate connection duration
            uint64_t ConnectionDuration = AckEvent->TimeNow - Connection->Stats.Timing.Start;
            
            // Calculate loss rate
            uint64_t TotalSent = Connection->Stats.Send.TotalPackets;
            uint64_t TotalLost = Connection->Stats.Send.SuspectedLostPackets;
            double LossRate = TotalSent > 0 ? ((double)TotalLost * 100.0) / (double)TotalSent : 0.0;
            
            // Write detailed BBR ACK log to file
            FILE* logFile = fopen("bbr_logs/quicbbr.txt", "a");
            if (logFile != NULL) {
                fprintf(logFile, "[BBR-PKT-ACKED] T=%lu.%03lu s, PKT=%lu, Size=%u B, "
                       "EstBW=%.2f Mbps, PacingRate=%.2f Mbps, DeliveryRate=%.2f Mbps, "
                       "RTT=%lu us, MinRTT=%lu us, CWND=%u B, InFlight=%u B, "
                       "Loss=%.2f%%, State=%s, TotalSent=%lu, TotalLost=%lu, PacingGain=%.2fx, CwndGain=%.2fx\n",
                       (unsigned long)(ConnectionDuration / 1000000),
                       (unsigned long)((ConnectionDuration % 1000000) / 1000),
                       (unsigned long)AckedPacket->PacketNumber,
                       AckedPacket->PacketLength,
                       EstimatedBandwidth / 1000000.0,
                       PacingRate / 1000000.0,
                       DeliveryRate / 1000000.0,
                       (unsigned long)SmoothedRtt,
                       (unsigned long)MinRtt,
                       CongestionWindow,
                       Bbr->BytesInFlight,
                       LossRate,
                       Bbr->BbrState == 0 ? "STARTUP" :
                       Bbr->BbrState == 1 ? "DRAIN" :
                       Bbr->BbrState == 2 ? "PROBE_BW" :
                       Bbr->BbrState == 3 ? "PROBE_RTT" : "UNKNOWN",
                       (unsigned long)TotalSent,
                       (unsigned long)TotalLost,
                       (double)Bbr->PacingGain / (double)GAIN_UNIT,  // Added PacingGain
                       (double)Bbr->CwndGain / (double)GAIN_UNIT);   // Added CwndGain
                fclose(logFile);
            }
            
            AckedPacket = AckedPacket->Next;
        }
    }

#ifdef QUIC_ENHANCED_PACKET_LOGGING
    // Enhanced packet level logging for acknowledged packets
    if (g_BbrPacketLoggerInitialized && AckEvent->AckedPackets != NULL) {
        QUIC_SENT_PACKET_METADATA* AckedPacket = AckEvent->AckedPackets;
        while (AckedPacket != NULL) {
            BbrPacketLevelLoggingRecordPacketAcknowledged(
                &g_BbrPacketLogger, Cc, AckedPacket->PacketNumber, 
                AckedPacket->PacketLength, AckEvent->TimeNow);
            AckedPacket = AckedPacket->Next;
        }
    }
#endif

    if (Connection->Settings.NetStatsEventEnabled) {
        BbrCongestionControlIndicateConnectionEvent(Connection, Cc);
    }

    // Generate periodic log
    BbrCongestionControlPeriodicLog(Cc);

    return BbrCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlOnDataLost(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_LOSS_EVENT* LossEvent
    )
{
    QUIC_CONGESTION_CONTROL_BBR *Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    QuicTraceEvent(
        ConnCongestionV2,
        "[conn][%p] Congestion event: IsEcn=%hu",
        Connection,
        FALSE);
    Connection->Stats.Send.CongestionCount++;

    BOOLEAN PreviousCanSendState = BbrCongestionControlCanSend(Cc);

    CXPLAT_DBG_ASSERT(LossEvent->NumRetransmittableBytes > 0);

    Bbr->EndOfRecoveryValid = TRUE;
    Bbr->EndOfRecovery = LossEvent->LargestSentPacketNumber;

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= LossEvent->NumRetransmittableBytes);
    Bbr->BytesInFlight -= LossEvent->NumRetransmittableBytes;

    // Log packet loss event (disabled for periodic logging)
    {
        const QUIC_PATH* Path = &Connection->Paths[0];
        uint64_t EstimatedBandwidth = BbrCongestionControlGetBandwidth(Cc);
        uint32_t CongestionWindow = BbrCongestionControlGetCongestionWindow(Cc);
        uint64_t SmoothedRtt = Path->GotFirstRttSample ? Path->SmoothedRtt : 0;
        uint64_t MinRtt = Bbr->MinRtt != UINT64_MAX ? Bbr->MinRtt : 0;
        uint64_t PacingRate = EstimatedBandwidth * Bbr->PacingGain / GAIN_UNIT;
        uint64_t DeliveryRate = Bbr->RecentDeliveryRate;
        
        // Calculate connection duration
        uint64_t CurrentTime = CxPlatTimeUs64();
        uint64_t ConnectionDuration = CurrentTime - Connection->Stats.Timing.Start;
        
        // Calculate loss rate
        uint64_t TotalSent = Connection->Stats.Send.TotalPackets;
        uint64_t TotalLost = Connection->Stats.Send.SuspectedLostPackets;
        double LossRate = TotalSent > 0 ? ((double)TotalLost * 100.0) / (double)TotalSent : 0.0;
        
        // Write detailed BBR loss log to file
        FILE* logFile = fopen("bbr_logs/quicbbr.txt", "a");
        if (logFile != NULL) {
            fprintf(logFile, "[BBR-PKT-LOST] T=%lu.%03lu s, PKT=%lu, Size=%u B, "
                   "EstBW=%.2f Mbps, PacingRate=%.2f Mbps, DeliveryRate=%.2f Mbps, "
                   "RTT=%lu us, MinRTT=%lu us, CWND=%u B, InFlight=%u B, "
                   "Loss=%.2f%%, State=%s, TotalSent=%lu, TotalLost=%lu, PersistentCongestion=%s, "
                   "PacingGain=%.2fx, CwndGain=%.2fx\n",
                   (unsigned long)(ConnectionDuration / 1000000),
                   (unsigned long)((ConnectionDuration % 1000000) / 1000),
                   (unsigned long)LossEvent->LargestPacketNumberLost,
                   LossEvent->NumRetransmittableBytes,
                   EstimatedBandwidth / 1000000.0,
                   PacingRate / 1000000.0,
                   DeliveryRate / 1000000.0,
                   (unsigned long)SmoothedRtt,
                   (unsigned long)MinRtt,
                   CongestionWindow,
                   Bbr->BytesInFlight,
                   LossRate,
                   Bbr->BbrState == 0 ? "STARTUP" :
                   Bbr->BbrState == 1 ? "DRAIN" :
                   Bbr->BbrState == 2 ? "PROBE_BW" :
                   Bbr->BbrState == 3 ? "PROBE_RTT" : "UNKNOWN",
                   (unsigned long)TotalSent,
                   (unsigned long)TotalLost,
                   LossEvent->PersistentCongestion ? "YES" : "NO",
                   (double)Bbr->PacingGain / (double)GAIN_UNIT,  // Added PacingGain
                   (double)Bbr->CwndGain / (double)GAIN_UNIT);   // Added CwndGain
            fclose(logFile);
        }
    }

#ifdef QUIC_ENHANCED_PACKET_LOGGING
    // Enhanced packet level logging for lost packets
    if (g_BbrPacketLoggerInitialized) {
        // Log the largest lost packet number as a representative
        BbrPacketLevelLoggingRecordPacketLost(
            &g_BbrPacketLogger, Cc, LossEvent->LargestPacketNumberLost, LossEvent->NumRetransmittableBytes);
    }
#endif

    uint32_t RecoveryWindow = Bbr->RecoveryWindow;
    uint32_t MinCongestionWindow = kMinCwndInMss * DatagramPayloadLength;

    if (!BbrCongestionControlInRecovery(Cc)) {
        Bbr->RecoveryState = RECOVERY_STATE_CONSERVATIVE;
        RecoveryWindow = Bbr->BytesInFlight;

        RecoveryWindow = CXPLAT_MAX(RecoveryWindow, MinCongestionWindow);

        Bbr->EndOfRoundTripValid = TRUE;
        Bbr->EndOfRoundTrip = LossEvent->LargestSentPacketNumber;
    }

    if (LossEvent->PersistentCongestion) {
        Bbr->RecoveryWindow = MinCongestionWindow;

        QuicTraceEvent(
            ConnPersistentCongestion,
            "[conn][%p] Persistent congestion event",
            Connection);
        Connection->Stats.Send.PersistentCongestionCount++;
    } else {
        Bbr->RecoveryWindow =
            RecoveryWindow > LossEvent->NumRetransmittableBytes + MinCongestionWindow
            ? RecoveryWindow - LossEvent->NumRetransmittableBytes
            : MinCongestionWindow;
    }

    BbrCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
    QuicConnLogBbr(QuicCongestionControlGetConnection(Cc));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlOnSpuriousCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    UNREFERENCED_PARAMETER(Cc);
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlSetAppLimited(
    _In_ struct QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR *Bbr = &Cc->Bbr;

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    uint64_t LargestSentPacketNumber = Connection->LossDetection.LargestSentPacketNumber;

    if (Bbr->BytesInFlight > BbrCongestionControlGetCongestionWindow(Cc)) {
        return;
    }

    Bbr->BandwidthFilter.AppLimited = TRUE;
    Bbr->BandwidthFilter.AppLimitedExitTarget = LargestSentPacketNumber;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlReset(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN FullReset
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    Bbr->CongestionWindow = Bbr->InitialCongestionWindowPackets * DatagramPayloadLength;
    Bbr->InitialCongestionWindow = Bbr->InitialCongestionWindowPackets * DatagramPayloadLength;
    Bbr->RecoveryWindow = kDefaultRecoveryCwndInMss * DatagramPayloadLength;
    Bbr->BytesInFlightMax = Bbr->CongestionWindow / 2;

    if (FullReset) {
        Bbr->BytesInFlight = 0;
    }
    Bbr->Exemptions = 0;

    Bbr->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
    Bbr->BbrState = BBR_STATE_STARTUP;
    Bbr->RoundTripCounter = 0;
    Bbr->CwndGain = kHighGain;
    Bbr->PacingGain = kHighGain;
    Bbr->BtlbwFound = FALSE;
    Bbr->SendQuantum = 0;
    Bbr->SlowStartupRoundCounter = 0 ;

    Bbr->PacingCycleIndex = 0;
    Bbr->AggregatedAckBytes = 0;
    Bbr->ExitingQuiescence = FALSE;
    Bbr->LastEstimatedStartupBandwidth = 0;

    Bbr->AckAggregationStartTimeValid = FALSE;
    Bbr->AckAggregationStartTime = CxPlatTimeUs64();
    Bbr->CycleStart = 0;

    Bbr->EndOfRecoveryValid = FALSE;
    Bbr->EndOfRecovery = 0;

    Bbr->ProbeRttRoundValid = FALSE;
    Bbr->ProbeRttRound = 0;

    Bbr->EndOfRoundTripValid = FALSE;
    Bbr->EndOfRoundTrip = 0;

    Bbr->ProbeRttEndTimeValid = FALSE;
    Bbr->ProbeRttEndTime = CxPlatTimeUs64();

    Bbr->RttSampleExpired = TRUE;
    Bbr->MinRttTimestampValid = FALSE;
    Bbr->MinRtt = UINT64_MAX;
    Bbr->MinRttTimestamp = 0;

    // Initialize recent delivery rate tracking fields
    Bbr->RecentSendRate = 0;
    Bbr->RecentAckRate = 0;
    Bbr->RecentDeliveryRate = 0;

    QuicSlidingWindowExtremumReset(&Bbr->MaxAckHeightFilter);

    QuicSlidingWindowExtremumReset(&Bbr->BandwidthFilter.WindowedMaxFilter);
    Bbr->BandwidthFilter.AppLimited = FALSE;
    Bbr->BandwidthFilter.AppLimitedExitTarget = 0;

    BbrCongestionControlLogOutFlowStatus(Cc);
    QuicConnLogBbr(Connection);
}


static const QUIC_CONGESTION_CONTROL QuicCongestionControlBbr = {
    .Name = "BBR",
    .QuicCongestionControlCanSend = BbrCongestionControlCanSend,
    .QuicCongestionControlSetExemption = BbrCongestionControlSetExemption,
    .QuicCongestionControlReset = BbrCongestionControlReset,
    .QuicCongestionControlGetSendAllowance = BbrCongestionControlGetSendAllowance,
    .QuicCongestionControlGetCongestionWindow = BbrCongestionControlGetCongestionWindow,
    .QuicCongestionControlOnDataSent = BbrCongestionControlOnDataSent,
    .QuicCongestionControlOnDataInvalidated = BbrCongestionControlOnDataInvalidated,
    .QuicCongestionControlOnDataAcknowledged = BbrCongestionControlOnDataAcknowledged,
    .QuicCongestionControlOnDataLost = BbrCongestionControlOnDataLost,
    .QuicCongestionControlOnEcn = NULL,
    .QuicCongestionControlOnSpuriousCongestionEvent = BbrCongestionControlOnSpuriousCongestionEvent,
    .QuicCongestionControlLogOutFlowStatus = BbrCongestionControlLogOutFlowStatus,
    .QuicCongestionControlGetExemptions = BbrCongestionControlGetExemptions,
    .QuicCongestionControlGetBytesInFlightMax = BbrCongestionControlGetBytesInFlightMax,
    .QuicCongestionControlIsAppLimited = BbrCongestionControlIsAppLimited,
    .QuicCongestionControlSetAppLimited = BbrCongestionControlSetAppLimited,
    .QuicCongestionControlLogPacketSent = BbrCongestionControlLogPacketSent,
};

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    )
{
    *Cc = QuicCongestionControlBbr;

    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    Bbr->InitialCongestionWindowPackets = Settings->InitialWindowPackets;

    Bbr->CongestionWindow = Bbr->InitialCongestionWindowPackets * DatagramPayloadLength;
    Bbr->InitialCongestionWindow = Bbr->InitialCongestionWindowPackets * DatagramPayloadLength;
    Bbr->RecoveryWindow = kDefaultRecoveryCwndInMss * DatagramPayloadLength;
    Bbr->BytesInFlightMax = Bbr->CongestionWindow / 2;

    Bbr->BytesInFlight = 0;
    Bbr->Exemptions = 0;

    Bbr->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
    Bbr->BbrState = BBR_STATE_STARTUP;
    Bbr->RoundTripCounter = 0;
    Bbr->CwndGain = kHighGain;
    Bbr->PacingGain = kHighGain;
    Bbr->BtlbwFound = FALSE;
    Bbr->SendQuantum = 0;
    Bbr->SlowStartupRoundCounter = 0 ;

    Bbr->PacingCycleIndex = 0;
    Bbr->AggregatedAckBytes = 0;
    Bbr->ExitingQuiescence = FALSE;
    Bbr->LastEstimatedStartupBandwidth = 0;
    Bbr->CycleStart = 0;

    Bbr->AckAggregationStartTimeValid = FALSE;
    Bbr->AckAggregationStartTime = CxPlatTimeUs64();

    Bbr->EndOfRecoveryValid = FALSE;
    Bbr->EndOfRecovery = 0;

    Bbr->ProbeRttRoundValid = FALSE;
    Bbr->ProbeRttRound = 0;

    Bbr->EndOfRoundTripValid = FALSE;
    Bbr->EndOfRoundTrip = 0;

    Bbr->ProbeRttEndTimeValid = FALSE;
    Bbr->ProbeRttEndTime = 0;

    Bbr->RttSampleExpired = TRUE;
    Bbr->MinRttTimestampValid = FALSE;
    Bbr->MinRtt = UINT64_MAX;
    Bbr->MinRttTimestamp = 0;

    Bbr->MaxAckHeightFilter = QuicSlidingWindowExtremumInitialize(
            kBbrMaxAckHeightFilterLen, kBbrDefaultFilterCapacity, Bbr->MaxAckHeightFilterEntries);

    Bbr->BandwidthFilter = (BBR_BANDWIDTH_FILTER) {
        .WindowedMaxFilter = QuicSlidingWindowExtremumInitialize(
                kBbrMaxBandwidthFilterLen, kBbrDefaultFilterCapacity, Bbr->BandwidthFilter.WindowedMaxFilterEntries),
        .AppLimited = FALSE,
        .AppLimitedExitTarget = 0,
    };

    // Initialize periodic logging fields
    Bbr->LastPeriodicLogTime = CxPlatTimeUs64();
    Bbr->LastLoggedSendBytes = 0;
    Bbr->LastLoggedRecvBytes = 0;
    Bbr->LastLoggedSentPackets = 0;
    Bbr->LastLoggedLostPackets = 0;

    // Initialize delay tracking fields
    Bbr->RecentSendDelay = 0;
    Bbr->RecentAckDelay = 0;

    QuicConnLogOutFlowStats(Connection);
    QuicConnLogBbr(Connection);

#ifdef QUIC_ENHANCED_PACKET_LOGGING
    // Initialize the global BBR packet logger if not already done
    if (!g_BbrPacketLoggerInitialized) {
        if (QUIC_SUCCEEDED(BbrPacketLevelLoggingInitialize(&g_BbrPacketLogger, 10000))) {
            g_BbrPacketLoggerInitialized = TRUE;
            printf("BBR Enhanced Packet Logging: Initialized with 10000 entries\n");
        }
    }
#endif
}

//
// Generate BBR performance summary when connection ends
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
BbrCongestionControlGeneratePerformanceSummary(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    const QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    const QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    const QUIC_PATH* Path = &Connection->Paths[0];
    
    // Use a simple flag to ensure we only print once per connection
    // This is a simple approach - in production you might want a more sophisticated mechanism
    static const QUIC_CONNECTION* LastConnection = NULL;
    if (LastConnection == Connection) {
        return; // Already printed for this connection
    }
    LastConnection = Connection;
    
    // Calculate connection duration
    uint64_t CurrentTime = CxPlatTimeUs64();
    uint64_t ConnectionDuration = CurrentTime - Connection->Stats.Timing.Start;
    
    // Calculate bandwidth metrics
    uint64_t EstimatedBandwidth = BbrCongestionControlGetBandwidth(Cc);
    uint32_t CongestionWindow = BbrCongestionControlGetCongestionWindow(Cc);
    
    // Calculate loss rate
    uint64_t TotalSent = Connection->Stats.Send.TotalPackets;
    uint64_t TotalLost = Connection->Stats.Send.SuspectedLostPackets;
    uint32_t LossRate = TotalSent > 0 ? (uint32_t)((TotalLost * 10000) / TotalSent) : 0;
    
    // Calculate actual bandwidth from bytes transferred
    uint64_t SendBytes = Connection->Stats.Send.TotalBytes;
    uint64_t RecvBytes = Connection->Stats.Recv.TotalBytes;
    uint64_t TotalBytes = SendBytes + RecvBytes;
    
    double SendBandwidthMbps = 0.0;
    double RecvBandwidthMbps = 0.0;
    double TotalBandwidthMbps = 0.0;
    
    if (ConnectionDuration > 0) {
        // Convert: bytes -> bits -> Mbps
        // bytes * 8 = bits, ConnectionDuration is in microseconds
        // (bits * 1,000,000) / ConnectionDuration = bits per second
        // bits per second / 1,000,000 = Mbps
        SendBandwidthMbps = ((double)SendBytes * 8.0 * 1000000.0) / ((double)ConnectionDuration * 1000000.0);
        RecvBandwidthMbps = ((double)RecvBytes * 8.0 * 1000000.0) / ((double)ConnectionDuration * 1000000.0);
        TotalBandwidthMbps = ((double)TotalBytes * 8.0 * 1000000.0) / ((double)ConnectionDuration * 1000000.0);
    }
    
    // Print BBR performance summary to file
    FILE* summaryFile = fopen("bbr_logs/quicbbr.txt", "a");
    if (summaryFile != NULL) {
        fprintf(summaryFile, "\n=== BBR Performance Summary ===\n");
        fprintf(summaryFile, "Connection Duration: %lu.%03lu s\n", 
               (unsigned long)(ConnectionDuration / 1000000), 
               (unsigned long)((ConnectionDuration % 1000000) / 1000));
        fprintf(summaryFile, "Debug: Start Time: %lu us, Current Time: %lu us, Duration: %lu us\n",
               (unsigned long)Connection->Stats.Timing.Start,
               (unsigned long)CurrentTime,
               (unsigned long)ConnectionDuration);
        fprintf(summaryFile, "BBR State: %s\n", 
               Bbr->BbrState == 0 ? "STARTUP" :
               Bbr->BbrState == 1 ? "DRAIN" :
               Bbr->BbrState == 2 ? "PROBE_BW" :
               Bbr->BbrState == 3 ? "PROBE_RTT" : "UNKNOWN");
        fprintf(summaryFile, "Estimated Bandwidth: %.2f Mbps\n", EstimatedBandwidth / 1000000.0);
        fprintf(summaryFile, "Send Bandwidth: %.2f Mbps\n", SendBandwidthMbps);
        fprintf(summaryFile, "Recv Bandwidth: %.2f Mbps\n", RecvBandwidthMbps);
        fprintf(summaryFile, "Total Bandwidth: %.2f Mbps\n", TotalBandwidthMbps);
        fprintf(summaryFile, "Congestion Window: %u bytes\n", CongestionWindow);
        fprintf(summaryFile, "Pacing Gain: %.2fx\n", (double)Bbr->PacingGain / (double)GAIN_UNIT);
        fprintf(summaryFile, "Cwnd Gain: %.2fx\n", (double)Bbr->CwndGain / (double)GAIN_UNIT);
        fprintf(summaryFile, "RTT: %lu us (Min: %lu us)\n", 
               (unsigned long)(Path->GotFirstRttSample ? Path->SmoothedRtt : 0), 
               (unsigned long)Bbr->MinRtt);
        fprintf(summaryFile, "Packets Sent: %lu\n", (unsigned long)TotalSent);
        fprintf(summaryFile, "Packets Lost: %lu (%.2f%%)\n", (unsigned long)TotalLost, LossRate / 100.0);
        fprintf(summaryFile, "Congestion Events: %u\n", Connection->Stats.Send.CongestionCount);
        fprintf(summaryFile, "Bytes Sent: %lu bytes\n", (unsigned long)SendBytes);
        fprintf(summaryFile, "Bytes Received: %lu bytes\n", (unsigned long)RecvBytes);
        fprintf(summaryFile, "Total Bytes: %lu bytes\n", (unsigned long)TotalBytes);
        fprintf(summaryFile, "Bytes In Flight: %u bytes\n", Bbr->BytesInFlight);
        fprintf(summaryFile, "App Limited: %s\n", BbrCongestionControlIsAppLimited(Cc) ? "YES" : "NO");
        fprintf(summaryFile, "==============================\n\n");
        fclose(summaryFile);
    }
}

//
// Generate periodic BBR performance log (every second)
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlPeriodicLog(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    const QUIC_PATH* Path = &Connection->Paths[0];
    
    uint64_t CurrentTime = CxPlatTimeUs64();
    uint64_t TimeSinceLastLog = CurrentTime - Bbr->LastPeriodicLogTime;
    
    // Log every 10ms (10,000 microseconds)
    if (TimeSinceLastLog < 10000) {
        return;
    }
    
    // Get current statistics
    uint64_t CurrentSendBytes = Connection->Stats.Send.TotalBytes;
    uint64_t CurrentRecvBytes = Connection->Stats.Recv.TotalBytes;
    uint64_t CurrentSentPackets = Connection->Stats.Send.TotalPackets;
    uint64_t CurrentLostPackets = Connection->Stats.Send.SuspectedLostPackets;
    
    // Calculate deltas since last log
    uint64_t DeltaSendBytes = CurrentSendBytes - Bbr->LastLoggedSendBytes;
    uint64_t DeltaRecvBytes = CurrentRecvBytes - Bbr->LastLoggedRecvBytes;
    uint64_t DeltaSentPackets = CurrentSentPackets - Bbr->LastLoggedSentPackets;
    uint64_t DeltaLostPackets = CurrentLostPackets - Bbr->LastLoggedLostPackets;
    
    // Calculate bandwidth (convert to Mbps)
    double SendBandwidthMbps = 0.0;
    double RecvBandwidthMbps = 0.0;
    double TotalBandwidthMbps = 0.0;
    
    if (TimeSinceLastLog > 0) {
        // Convert: bytes -> bits -> Mbps
        // (bytes * 8 * 1,000,000) / TimeSinceLastLog = bits per second
        // bits per second / 1,000,000 = Mbps
        SendBandwidthMbps = ((double)DeltaSendBytes * 8.0 * 1000000.0) / ((double)TimeSinceLastLog * 1000000.0);
        RecvBandwidthMbps = ((double)DeltaRecvBytes * 8.0 * 1000000.0) / ((double)TimeSinceLastLog * 1000000.0);
        TotalBandwidthMbps = SendBandwidthMbps + RecvBandwidthMbps;
    }
    
    // Use delta lost packets for this time interval
    uint64_t IntervalLostPackets = DeltaLostPackets;
    
    // Get BBR metrics
    uint64_t EstimatedBandwidth = BbrCongestionControlGetBandwidth(Cc);
    uint32_t CongestionWindow = BbrCongestionControlGetCongestionWindow(Cc);
    uint64_t SmoothedRtt = Path->GotFirstRttSample ? Path->SmoothedRtt : 0;
    uint64_t MinRtt = Bbr->MinRtt != UINT64_MAX ? Bbr->MinRtt : 0;
    
    // Calculate pacing rate: Bandwidth * PacingGain / GAIN_UNIT
    uint64_t PacingRate = EstimatedBandwidth * Bbr->PacingGain / GAIN_UNIT;
    double PacingRateMbps = PacingRate / 1000000.0;
    
    // Debug: Show pacing gain value
    double PacingGainRatio = (double)Bbr->PacingGain / (double)GAIN_UNIT;
    
    // Get delivery rate from BBR structure (already calculated as min(send rate, ack rate))
    uint64_t DeliveryRate = Bbr->RecentDeliveryRate;
    double DeliveryRateMbps = DeliveryRate / 1000000.0;
    
    // Calculate connection duration
    uint64_t ConnectionDuration = CurrentTime - Connection->Stats.Timing.Start;
    
    // Print periodic log to file
    FILE* logFile = fopen("bbr_logs/quicbbr.txt", "a");
    if (logFile != NULL) {
        fprintf(logFile, "[BBR-LOG] T=%lu.%03lu s, Send=%.2f Mbps, Recv=%.2f Mbps, Total=%.2f Mbps, "
                "EstBW=%.2f Mbps, PacingRate=%.2f Mbps, PacingGain=%.2fx, CwndGain=%.2fx, DeliveryRate=%.2f Mbps, "
                "RTT=%lu us, MinRTT=%lu us, CWND=%u B, InFlight=%u B, "
                "Lost=%lu, State=%s, Pkts=%lu/%lu, Bytes=%lu/%lu, "
                "SendDelay=%lu us, AckDelay=%lu us\n",
                (unsigned long)(ConnectionDuration / 1000000),
                (unsigned long)((ConnectionDuration % 1000000) / 1000),
                SendBandwidthMbps,
                RecvBandwidthMbps,
                TotalBandwidthMbps,
                EstimatedBandwidth / 1000000.0,
                PacingRateMbps,
                PacingGainRatio,
                (double)Bbr->CwndGain / (double)GAIN_UNIT,
                DeliveryRateMbps,
                (unsigned long)SmoothedRtt,
                (unsigned long)MinRtt,
                CongestionWindow,
                Bbr->BytesInFlight,
                (unsigned long)IntervalLostPackets,
                Bbr->BbrState == 0 ? "STARTUP" :
                Bbr->BbrState == 1 ? "DRAIN" :
                Bbr->BbrState == 2 ? "PROBE_BW" :
                Bbr->BbrState == 3 ? "PROBE_RTT" : "UNKNOWN",
                (unsigned long)DeltaSentPackets,
                (unsigned long)DeltaLostPackets,
                (unsigned long)DeltaSendBytes,
                (unsigned long)DeltaRecvBytes,
                (unsigned long)Bbr->RecentSendDelay,
                (unsigned long)Bbr->RecentAckDelay);
        fclose(logFile);
    }
    
    // Update last logged values
    Bbr->LastPeriodicLogTime = CurrentTime;
    Bbr->LastLoggedSendBytes = CurrentSendBytes;
    Bbr->LastLoggedRecvBytes = CurrentRecvBytes;
    Bbr->LastLoggedSentPackets = CurrentSentPackets;
    Bbr->LastLoggedLostPackets = CurrentLostPackets;
}
