import { Transaction } from "ethereumjs-tx"

export interface IKeyring<T> {
  type: string,
  serialize(): Promise<T>
  deserialize(obj: T): Promise<void>
  addAccounts(n: number): Promise<void>
  getAccounts(): Promise<string[]>
  signTransaction(address: string, transaction: Transaction): Promise<Transaction>
  signMessage(address: string, data: string): Promise<string>
  getEncryptionPublicKey(address: string): Promise<string>
  decryptMessage(address: string, data: string): Promise<string>
  exportAccount(address: string): Promise<void>
  removeAccount(address: string): Promise<void>
}

export interface IBitfiKeyring<T> extends IKeyring<T> {
  signPersonalMessage(ddress: string, data: string): Promise<string>,
}

//export type Callback<T extends (EnvoyMessage | BitfiMessage)> = (mes: T) => void

