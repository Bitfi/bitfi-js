import { IDeviceListener } from "../types"
import { WebSocket } from "ws"
import { DeviceEvent, DeviceEventCallback, DeviceEventType, DeviceMessage, DeviceMessageRaw } from "./types"
import { toCamel } from "../utils/toCamel"
import { DeviceError } from "./errors"

const defaultSubscribers = {
  [DeviceEventType.Battery]: {},
  [DeviceEventType.Availability]: {},
  [DeviceEventType.Session]: {},
  [DeviceEventType.Error]: {}
}

export class Listener implements IDeviceListener {
  private readonly _envoy: string
  private readonly _websocket: WebSocket
  private _counter: number
  private _restartAttempt: number
  
  private _subscribers: { 
    [event in DeviceEventType]: Record<number, DeviceEventCallback<event>> 
  } = { ...defaultSubscribers }

  constructor(envoy: string, url: string, wsProvider: WebSocket) {
    this._envoy = envoy
    //@ts-ignore
    this._websocket = new wsProvider(url)
    this._counter = 0
    this._restartAttempt = 1
    this._startListener()
  }
  
  public subscribe<T extends DeviceEventType>(eventType: T, callback: DeviceEventCallback<T>): () => void {
    this._counter++
    const id = this._counter
    //@ts-ignore
    this._subscribers[eventType][id] = callback
    return () => delete this._subscribers[eventType][id]
  }

  public close() {
    this._websocket.close()
    this._subscribers = { ...defaultSubscribers }
  }

  private _restart() {
    const timeoutMsec = Math.pow(2, this._restartAttempt) * 1000
    this._restartAttempt++
    console.log(`restarting in ${timeoutMsec / 1000} seconds`)

    setTimeout(() => {
      this._startListener()
    }, timeoutMsec)
  }

  private _notify<T extends DeviceEventType>(type: T, event: DeviceEvent[T]) {
    for (const subscriber of Object.values(this._subscribers[type])) {
      //@ts-ignore
      subscriber(event)
    }
  }

  private _startListener() {
    console.log(this._envoy)
    this._websocket.addEventListener("open", (event) => {
      this._websocket.send(JSON.stringify({ ClientToken: this._envoy }));
    });

    this._websocket.addEventListener('close', (e) => {
      console.log(`CLOSED WITH CODE ${e.code}`)
    })
    this._websocket.addEventListener('error', this._restart.bind(this))

    this._websocket.addEventListener("message", (e) => {
      console.log(e.data)
      
      if (!e.data)
        return

      var obj = toCamel(JSON.parse(e.data.toString())) as DeviceMessageRaw;
      var message = obj.message;
      
      if (message) {
        const mes = toCamel(JSON.parse(Buffer.from(message, 'base64').toString('utf-8'))) as DeviceMessage<any>
        console.log(mes)
        if (mes.event_info && mes.event_type && this._subscribers[mes.event_type]) {
          switch (mes.event_type) {
            case DeviceEventType.Session: {
              const payload = mes.event_info as DeviceEvent[DeviceEventType.Session]
              this._notify(mes.event_type, payload)
              this._restart()
              break
            }
            default: {
              this._notify(mes.event_type, mes.event_info)
            }
          }
          
        }
      }

      const error = obj.error;

      if (error) {
        console.log(error)
        this._notify(DeviceEventType.Error, new DeviceError(error, 0))
      }
    })
  }
}