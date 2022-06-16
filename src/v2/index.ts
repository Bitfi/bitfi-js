export { default as BitfiV2 } from './bitfi'
export type {
  DeviceInfo,
  Signature,
  BitfiDump,
  Symbol as SupportedCurrency,
  EthLikeSymbol,
  DagSignedTransaction,
  DagLastTxRef,
  TransferResponse,
  LegacyProfile,
  WalletAddress,
  SegwitSupportedSymbol
} from './types'
export { TransferType, EventType, ConnectionStatus } from './types'
export * from './errors'