export class TimeoutError extends Error {
  message: string
  constructor() {
    super()
    this.message = "Timeout Error"
  }
}