import { DeviceInfo, EthLikeSymbol, Symbol, TransferParams, TransferType } from "../v2/types"
import { Transaction } from "ethereumjs-tx"

export interface IEthKeyring<T> {
  type: string,
  serialize(): Promise<T>
  deserialize(obj: T): Promise<void>
  addAccounts(n: number): Promise<void>
  getAccounts(symbol: Symbol): Promise<string[]>
  signMessage(address: string, data: Buffer | string, symbol: Symbol): Promise<string>
  getEncryptionPublicKey(address: string): Promise<string>
  decryptMessage(address: string, data: string): Promise<string>
  exportAccount(address: string): Promise<void>
  removeAccount(address: string): Promise<void>
  signTransaction(address: string, transaction: Transaction, symbol: EthLikeSymbol): Promise<Transaction>
}

export interface IBitfiKeyring<T> extends IEthKeyring<T> {
  ping(): Promise<boolean>
  authorize(onSessionCodeReceived: (code: string) => void): Promise<boolean>
  getDeviceInfo(): Promise<DeviceInfo>
  transfer<B extends TransferType>(params: TransferParams[B]): Promise<string>
  getPublicKeys(symbol: Symbol)
  getDeviceEnvoy(): Promise<string>
}
