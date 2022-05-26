export type BitfiKeyringSerialized = {
  publicKey: string,
  appSecret: string,
  authToken: string,
  config: BitfiConfig
}

export type BitfiConfig = {
  envoyUrl: string,
  apiUrl: string
}

export type SignedMessageResponse = {
  success: boolean,
  nodeResponse: string,
  signatureResponse: string
}

export type SignedTransactionResponse = {
  Success: boolean,
  Response: {
    toAddress: string,
    fullySigned: boolean,
    txnBroadcast: boolean,
    signedTransaction: string
  }
}

export type BitfiMessage = {
  user_message: string,
  display_code: string,
  completed: boolean,
  notified: boolean,
  signature_der?: string,
  request_id?: string,
  public_key?: string,
  error_message?: string
}

export type EnvoyMessage = {
  error_message?: string
  ticks: string,
  user_message: string,
  completed: boolean
}

export type SignInParams = {
  appSecret: string,
  signData: string,
  url: string,
  deviceId: string,
  onMessage?: Callback<BitfiMessage>,
  onNotified?: () => void,
  config: BitfiConfig,
}

export type Callback<T extends (EnvoyMessage | BitfiMessage)> = (mes: T) => void