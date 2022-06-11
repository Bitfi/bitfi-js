import { IBitfiKeyring, IDeviceListener } from "../types"
import { WebSocket } from "ws"
import { DeviceEvent, DeviceEventCallback, EventType, DeviceMessage, DeviceMessageRaw } from "./types"
import { toCamel } from "../utils/toCamel"
import { DeviceError } from "./errors"

const defaultSubscribers = {
  [EventType.Battery]: {},
  [EventType.Availability]: {},
  [EventType.Session]: {},
  [EventType.Error]: {},
  [EventType.Closed]: {}
}

export class Listener implements IDeviceListener {
  private _envoy: string
  private _websocket: WebSocket
  private _counter: number
  private _monitorFrequencyMsec: number
  private _checker: any 
  private readonly _wsProvider: WebSocket
  private readonly _url: string
  private readonly _wallet: IBitfiKeyring<any>
  
  private _subscribers: { 
    [event in EventType]: Record<number, DeviceEventCallback<event>> 
  } = { ...defaultSubscribers }

  private constructor(wallet: IBitfiKeyring<any>, url: string, wsProvider: WebSocket, monitorFrequencyMsec: number = 3000) {
    this._wallet = wallet
    this._websocket = null
    this._counter = 0
    this._wsProvider = wsProvider
    this._url = url
    this._monitorFrequencyMsec = monitorFrequencyMsec
  }
  
  public subscribe<T extends Exclude<EventType, EventType.Session>>(
    eventType: T, callback: DeviceEventCallback<T>
  ): () => void {
    this._counter++
    const id = this._counter
    //@ts-ignore
    this._subscribers[eventType][id] = callback
    return () => delete this._subscribers[eventType][id]
  }

  public stop() {
    clearInterval(this._checker)
    this._websocket.close()
    this._websocket = null
    this._notify(EventType.Closed, null)
  }
  
  private _monitor() {
    if (this._websocket && this._websocket.readyState !== this._websocket.CLOSED) {
      return
    }
    
    this._start()
  }

  private _notify<T extends EventType>(type: T, event: DeviceEvent[T]) {
    for (const subscriber of Object.values(this._subscribers[type])) {
      //@ts-ignore
      subscriber(event)
    }
  }

  private _start() {
    if (this._websocket && this._websocket.readyState !== this._websocket.CLOSED) {
      throw new Error('Websocket is running already')
    }
    
    console.log('Starting websocket')

    //@ts-ignore
    this._websocket = new this._wsProvider(this._url)

    this._websocket.addEventListener("open", async (event) => {
      this._websocket.send(JSON.stringify({ ClientToken: this._envoy }));
    });

    this._websocket.addEventListener('close', (e) => {
      console.log(`CLOSED WITH CODE ${e.code}`)
    })

    this._websocket.addEventListener('error', () => {
      console.log('error')
    })

    this._websocket.addEventListener("message", (e) => {
      if (!e.data)
        return

      var obj = toCamel(JSON.parse(e.data.toString())) as DeviceMessageRaw;
      var message = obj.message;
      
      if (message) {
        const mes = toCamel(JSON.parse(Buffer.from(message, 'base64').toString('utf-8'))) as DeviceMessage<any>

        if (mes.event_info && mes.event_type && this._subscribers[mes.event_type]) {
          switch (mes.event_type) {
            case EventType.Session: {
              const payload = mes.event_info as DeviceEvent[EventType.Session]

              if (payload.isDisposed) {
                // user closed the session
                this.stop()
              }
            }
          }

          this._notify(mes.event_type, mes.event_info)
        }
      }

      const error = obj.error;

      if (error) {
        console.log(error)
        this._notify(EventType.Error, new DeviceError(error, 0))
      }
    })
  }

  public async start(): Promise<void> {
    const envoy = await this._wallet.getDeviceEnvoy()

    this._envoy = envoy
    this._checker = setInterval(this._monitor.bind(this), this._monitorFrequencyMsec)
    this._start()
  }
}