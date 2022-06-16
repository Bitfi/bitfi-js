import { IBitfiKeyring, IDeviceListener } from "../types"
import { WebSocket } from "ws"
import { DeviceEvent, DeviceEventCallback, EventType, DeviceMessage, DeviceMessageRaw, ConnectionStatus } from "./types"
import { toCamel } from "../utils/toCamel"
import { ConnectionError, DeviceError } from "./errors"

const defaultSubscribers = {
  [EventType.Battery]: {},
  [EventType.Availability]: {},
  [EventType.Session]: {},

  [EventType.ConnectionError]: {},
  [EventType.ConnectionStatus]: {},
  [EventType.SessionClosed]: {}
}

export class Listener implements IDeviceListener {
  private _envoy: string
  private _websocket: WebSocket
  private _counter: number
  private _monitorFrequencyMsec: number
  private _checker: any 
  private _lastTick: number
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
    this._websocket
      .removeAllListeners('close')
      .removeAllListeners('message')
      .removeAllListeners('open')
      .removeAllListeners('error')

    this._notify(EventType.ConnectionStatus, ConnectionStatus.Disconnected)
    //this._websocket = null
  }
  
  private _monitor() {
    if (!this._isClosing()) {
      if (this._lastTick !== undefined && Date.now() - this._lastTick > 5 * 1000) {
        console.log('No ticks...')
        this._websocket.close()
      } else {
        return
      }
    }
    
    this._start()
  }

  private _notify<T extends EventType>(type: T, event: DeviceEvent[T]) {
    
    for (const subscriber of Object.values(this._subscribers[type])) {
      //@ts-ignore
      subscriber(event)
    }
  }

  private _isClosing() {
    return !this._websocket || this._websocket.readyState === this._websocket.CLOSING || 
      this._websocket.readyState === this._websocket.CLOSED
  }

  private _start() {
    if (!this._isClosing()) {
      throw new Error('Websocket is running already')
    }
    
    console.log('Starting websocket')
    this._notify(EventType.ConnectionStatus, ConnectionStatus.Connecting)

    //@ts-ignore
    this._websocket = new this._wsProvider(this._url)

    this._websocket.addEventListener("open", async (event) => {
      this._websocket.send(JSON.stringify({ ClientToken: this._envoy }));
      this._notify(EventType.ConnectionStatus, ConnectionStatus.Connected)
    });

    this._websocket.addEventListener('close', (e) => {
      console.log(`CLOSED WITH CODE ${e.code}`)
      this._notify(EventType.ConnectionStatus, ConnectionStatus.Disconnected)
    })

    this._websocket.addEventListener('error', () => {
      console.log('error')
    })

    this._websocket.addEventListener("message", (e) => {
      if (!e.data || this._isClosing()) {
        return 
      }

      var obj = toCamel(JSON.parse(e.data.toString())) as DeviceMessageRaw;
      
      if (obj.ticks) {
        this._lastTick = Date.now()
      }

      var message = obj.message;
      
      if (message) {
        const mes = toCamel(JSON.parse(Buffer.from(message, 'base64').toString('utf-8'))) as DeviceMessage<any>

        if (mes.event_info && mes.event_type && this._subscribers[mes.event_type]) {
          switch (mes.event_type) {
            case EventType.Session: {
              const payload = mes.event_info as DeviceEvent[EventType.Session]

              if (payload.isDisposed) {
                // user closed the session
                this._notify(EventType.SessionClosed, undefined)
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
        this._notify(EventType.ConnectionError, new ConnectionError(error))
      }
    })
  }

  public async start(envoyToken?: string): Promise<void> {
    this._envoy = envoyToken || await this._wallet.getDeviceEnvoy()
    this._checker = setInterval(this._monitor.bind(this), this._monitorFrequencyMsec)
    this._start()
  }
}