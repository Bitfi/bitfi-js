export type DeviceInfo = {
  devicePubKey: string,
  signerPubKey: string,
  runningVersion: string,
  availableMem: string,
  deviceTime: string,
  uptimeElapsed: string,
  uptimeAwake: string,
  isRestartPending: boolean,
  isVibeEnabled: boolean,
  isAutoUpdate: boolean,
  processList: string[]
}

export type Symbol = 'eth' 

export type Transaction = {
  transaction: string
}

export type Addresses = {
  addresses: string[]
}

export type Result<T> = {
  result: T
}

export type Signature = {
  signature: string
}
