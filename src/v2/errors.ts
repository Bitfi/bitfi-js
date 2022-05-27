export class TimeoutError extends Error {
  constructor() {
    super("Timeout Error")
    Object.setPrototypeOf(this, TimeoutError.prototype);
  }
}

export class DeviceError extends Error {
  public readonly code: number

  constructor(message: string, code: number) {
    super(message)
    this.code = code

    Object.setPrototypeOf(this, DeviceError.prototype);
  }
}