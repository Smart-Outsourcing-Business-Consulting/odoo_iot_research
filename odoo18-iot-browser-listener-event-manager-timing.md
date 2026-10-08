# Odoo 18 IoT Browser Listener, Event Manager, and Timing Limits

## Purpose

This note records how the Odoo 18.0 browser-side IoT listener works with the
IoT Box `hw_drivers` event manager, what role `event_manager` plays inside
Odoo IoT, and which timing limits apply to browser listeners, device actions,
event replay, retry, and session expiry.

The immediate conclusion is:

- the browser listener is a live local notification path, not a durable result
  ledger;
- `device.action(...)` timing and `/hw_drivers/event` listener timing are
  separate mechanisms;
- a "persistent" browser listener is only a self-renewing active longpoll loop,
  not a permanent server-side subscription;
- Odoo's browser listener map supports one callback entry per IoT device
  identifier in a browser session, so competing permanent and ephemeral
  `device.addListener(...)` calls for the same device are mutually exclusive at
  the Odoo listener API layer;
- Odoo 18.0 source inspected here contains a 6 second action timeout, a 50
  second server longpoll wait, a 60 second browser longpoll timeout, a roughly
  5 second replay window, and a 70 second listener-session expiry;
- no 7 second listener or action timeout was found in the inspected Odoo 18.0
  IoT source paths.

## Source-Proof Scope

This is source proof only. No Odoo server, browser session, IoT Box runtime,
database, fiscal printer, or hardware device was started.

Odoo source paths below are relative to the relevant Odoo 18.0 checkout root.
Odoo Enterprise source is local/private provenance, so this note copies the
relevant findings instead of using machine-local absolute links. Odoo Community
`hw_drivers` source can also be checked against the public Odoo 18.0 branch.

## Source Reference Convention

Odoo 18.0 Enterprise source paths:

1. `enterprise/iot/static/src/device_controller.js`
2. `enterprise/iot/static/src/iot_longpolling.js`
3. `enterprise/pos_iot/static/src/overrides/models/pos_store.js`
4. `enterprise/pos_iot/static/src/overrides/components/iot_longpolling/iot_longpolling.js`

Odoo 18.0 Community source paths:

1. `odoo/addons/hw_drivers/controllers/driver.py`
2. `odoo/addons/hw_drivers/event_manager.py`

Addon source path:

1. `static/src/overrides/printer/iot_printer.js`

## POS Browser Listener Entry Points

In Odoo 18.0 POS IoT, POS-loaded IoT devices become browser-side
`DeviceController` instances. `pos_iot` creates those controllers from POS
device records and stores them in `hardwareProxy.deviceControllers`, including
printer, scanner, scale, and payment terminal devices.

`DeviceController` is the POS-facing wrapper most addon code interacts with:

- `DeviceController.action(data, fallback)` delegates to
  `iotLongpolling.action(iotIp, identifier, data, fallback)`;
- `DeviceController.addListener(callback, fallback)` delegates to
  `iotLongpolling.addListener(iotIp, [identifier], listenerId, callback,
  fallback)`;
- `DeviceController.removeListener()` delegates to
  `iotLongpolling.removeListener(iotIp, identifier, listenerId)`.

```text
[POS component or addon]
        |
        | device.addListener(callback)
        v
[DeviceController]
        |
        | iotLongpolling.addListener(iot_ip, [identifier], listener_id)
        v
[IoTLongpolling browser service]
        |
        | POST /hw_drivers/event with listener state
        v
[IoT Box local Odoo controller]
        |
        | event_manager.add_request(listener)
        v
[hw_drivers EventManager]
```

The diagram shows the browser listener registration path. It does not imply a
cloud Odoo backend or websocket hop. The browser posts directly to the local
IoT Box `/hw_drivers/event` route selected from the IoT device IP.

## Browser Listener Multiplexing Restriction

`IoTLongpolling.addListener(...)` maintains one listener state object per
`iot_ip`. Inside that state, `devices` is a map keyed by device identifier. For
each requested device, `addListener(...)` writes:

```text
_listeners[iot_ip].devices[device_identifier] =
  { listener_id, device_identifier, callback }
```

That means one browser `iot_longpolling` service can listen to multiple
different devices at the same IoT Box, but it does not preserve multiple
callbacks for the same device identifier.

```text
Supported by Odoo listener map

_listeners[box_ip].devices
  printer_1  -> callback A
  scale_1    -> callback B
  scanner_1  -> callback C

One longpoll loop can fan in events for different device identifiers.
```

```text
Not supported safely through raw device.addListener(...)

_listeners[box_ip].devices
  printer_1  -> callback A

second addListener(printer_1, callback B)

_listeners[box_ip].devices
  printer_1  -> callback B

The later registration replaces the callback entry for the same device key.
```

Therefore a model that uses both a long-lived fiscal listener and separate
ephemeral Odoo listeners for the same fiscal printer is not a true hybrid at
the Odoo API layer. Those registrations compete for the same map entry.

The viable hybrid shape is above Odoo's listener API: use one underlying Odoo
listener per fiscal device, then fan out inside addon-owned code.

```text
[single Odoo device.addListener for fiscal printer]
        |
        v
[addon fiscal event hub]
  - dispatches live UI signals
  - resolves pending waiters by correlation id
  - supports diagnostics subscribers
  - ignores unrelated device events
```

This keeps the Odoo listener registration stable while allowing long-lived UI
observation and ephemeral command waiters to coexist in addon state.

## Event Manager Role In `hw_drivers`

`event_manager` is an in-process coordination object in the IoT Box
`hw_drivers` runtime. It owns:

- `events`: an in-memory list of recently observed device events;
- `sessions`: an in-memory map keyed by browser listener session id;
- one Python `threading.Event` per active listener request.

`DriverController.event(listener)` handles the browser's longpoll request. It
first calls `event_manager.add_request(listener)`, then searches recent
`event_manager.events` for a matching device event newer than the browser's
`last_event`. If no matching previous event is available, the controller waits
for the session's Python event to be set.

`EventManager.device_changed(device)` is the producer-side fanout hook. It
builds an event from `device.data`, adds the device identifier and event time,
stores optional request data, appends the event to `events`, and wakes any
active listener session whose `devices` set contains the changed device
identifier.

```text
[IoT driver code]
        |
        | event_manager.device_changed(device)
        v
[EventManager]
  - append event to memory list
  - find matching sessions by device_identifier
  - set waiting Python Event
        |
        | wakes blocked controller request
        v
[/hw_drivers/event response]
        |
        | JSON result to browser longpoll
        v
[IoTLongpolling._onSuccess]
  - update last_event
  - call registered device callback
  - open next poll if listeners remain
```

This is live fanout plus a short replay buffer. It is not durable storage, a
cloud bus, or an authoritative audit trail. Process restart, session expiry,
long browser gaps, or an event older than the replay window can lose the live
notification.

## Action Path Versus Listener Path

The action path and listener path are separate HTTP requests. A typical action
that later emits a live event looks like this:

```text
[POS browser]
  | 1. device.addListener(callback)
  |    opens/restarts /hw_drivers/event longpoll
  |
  | 2. device.action(data)
  |    POST /hw_drivers/action
  v
[DriverController.action]
  | synchronous iot_device.action(data)
  v
[IoT driver]
  | may call event_manager.device_changed(device)
  v
[EventManager]
  | wakes waiting /hw_drivers/event request
  v
[POS browser callback]
```

The listener should be registered before the action when the event is expected
to correlate with the action. Registering after the action relies on the short
previous-event replay window.

## Timing Limits

The inspected source contains these limits:

| Limit | Source Symbol Or Code | Path | Meaning |
|---:|---|---|---|
| `6000 ms` | `ACTION_TIMEOUT = 6000` | `enterprise/iot/static/src/iot_longpolling.js` | Browser-side timeout for `device.action(...)` POSTs to `/hw_drivers/action`. |
| `60000 ms` | `POLL_TIMEOUT = 60000` | `enterprise/iot/static/src/iot_longpolling.js` | Browser-side timeout for `/hw_drivers/event` longpoll requests. |
| `50 s` | `req['event'].wait(50)` | `odoo/addons/hw_drivers/controllers/driver.py` | Server-side wait for a new matching event before the longpoll returns empty. |
| `~5 s` | `oldest_time = time.time() - 5` | `odoo/addons/hw_drivers/controllers/driver.py` | Previous events older than about 5 seconds are removed while checking replay. |
| `70 s` | `_delete_expired_sessions(max_time=70)` | `odoo/addons/hw_drivers/event_manager.py` | Listener sessions with no request activity for more than 70 seconds are deleted. |
| `1.5 s` to `15 s` | `RPC_DELAY = 1500`; `MAX_RPC_DELAY = 1500 * 10` | `enterprise/iot/static/src/iot_longpolling.js` | Browser retry backoff after poll errors. |
| `15000 ms` | `FISCAL_RESULT_WAIT_TIMEOUT_MS = 15000` | `static/src/overrides/printer/iot_printer.js` | Addon-specific wait for a terminal fiscal result event. Not an Odoo core limit. |

### Healthy Longpoll Cycle

```text
t0 browser POST /hw_drivers/event
 |
 | browser AJAX timeout: 60s
 v
[IoT Box DriverController.event]
 |
 | server wait: up to 50s
 |
 +-- matching event before 50s --> return event to browser
 |
 +-- no event by 50s ---------> return empty result
                                  browser immediately opens next poll
```

The `60s` browser timeout is not the server wait. It is a client-side margin
around the `50s` server wait. Odoo's own comment says the backend has a maximum
cycle time of 50 seconds and the browser gives it 10 additional seconds.

### Previous-Event Replay Window

```text
event E stored at time e
        |
        | browser next poll starts at time p
        v
p - e <= ~5s and event.time > last_event?
        |
        +-- yes --> replay event from memory list
        |
        +-- no  --> old event can be deleted or ignored
```

This replay window is the tightest durability-related limit in the listener
path. A self-renewing active listener is only useful while polling remains
healthy enough that gaps stay below this window, or while a request is already
waiting when the event arrives.

### Session Expiry Versus Self-Renewing Polling

```text
healthy active listener

t0       browser POST /hw_drivers/event
t0-50s   IoT Box waits for event
t50      empty response if no event arrived
t50+     browser opens next /hw_drivers/event
         EventManager.add_request(...) refreshes time_request

time since last request stays below 70s
```

The 70 second session expiry does not make a server-side listener permanent.
It only permits a healthy longpoll loop to keep refreshing its in-memory
session before expiry.

```text
interrupted listener

last successful /hw_drivers/event request at t0
        |
        | no request reaches IoT Box for more than 70s
        v
EventManager._delete_expired_sessions(...) can remove session
        |
        v
browser must recreate listener state on a later poll
```

So "persistent browser listener" is imprecise language. The accurate model is
"self-renewing active longpoll listener while POS UI remains active and
network/runtime conditions keep the poll loop healthy."

### Retry And Replay Coupling

```text
poll request fails or times out unexpectedly
        |
        v
_onError increments retries
        |
        | delay = min(1.5s * retries, 15s)
        v
browser starts polling again
        |
        v
events produced during the gap must still be inside the ~5s replay window
```

The retry backoff can grow larger than the previous-event replay window. This
means the listener can miss events during network, browser, or IoT Box
interruptions even when polling later recovers.

### Action Timeout Is Independent

```text
[device.action POST /hw_drivers/action]
        |
        | browser timeout: 6s
        v
[DriverController.action]
        |
        | synchronous iot_device.action(data)
        v
[driver execution]

[listener POST /hw_drivers/event]
        |
        | server wait: 50s
        | browser timeout: 60s
        v
[event callback if event arrives]
```

The `6s` action timeout does not cap the listener's wait. It caps the browser's
action request. The source proves that the browser gives up on the action
request after 6 seconds. Whether a timed-out HTTP request continues executing
inside a specific runtime deployment requires runtime proof.

No inspected Odoo 18.0 source path contained a `7s` or `7000 ms` listener or
action timeout. If a 7 second limit appears in a runtime observation, likely
candidates are custom code, external proxy/browser behavior, a rounded
description of the 6 second action timeout, or a different Odoo version/path.

## Consequences For Listener Design

Use the browser listener as a self-renewing active longpoll listener for
non-authoritative live UI signals when all of the following are acceptable:

- the POS browser is active;
- the IoT Box process is alive;
- the poll loop stays healthy;
- missed notifications can be recovered by another authoritative read or
  refresh path.

Do not use the browser listener as the only source of fiscal evidence. The
event manager's state is in memory, prior events have a roughly 5 second replay
window, and browser retry gaps can exceed that replay window.

Do not create competing permanent and ephemeral `device.addListener(...)`
registrations for the same fiscal printer. The Odoo listener API stores one
callback per device identifier in the browser listener map. Use one underlying
listener and addon-owned fanout if both long-lived UI observation and
per-command waiters are needed.

For fiscal command flows that use the listener as a convenience path:

- register the listener before sending the action;
- correlate events explicitly, for example by idempotency or dispatch id;
- handle action timeout and listener timeout separately;
- persist fiscal evidence through an authoritative backend callback or durable
  result projection;
- treat live listener events as latency optimization, not as the ledger.

## Source Summary

Relevant Odoo 18.0 symbols inspected:

- `DeviceController.action(...)`
- `DeviceController.addListener(...)`
- `DeviceController.removeListener(...)`
- `IoTLongpolling.addListener(...)`
- `IoTLongpolling.removeListener(...)`
- `IoTLongpolling.action(...)`
- `IoTLongpolling._poll(...)`
- `IoTLongpolling._onSuccess(...)`
- `IoTLongpolling._onError(...)`
- `DriverController.action(...)`
- `DriverController.event(...)`
- `EventManager.add_request(...)`
- `EventManager.device_changed(...)`
- `EventManager._delete_expired_sessions(...)`

Conclusion type: source proof only. Runtime proof would require a live Odoo
18.0 POS session, IoT Box process, browser trace, and controlled event/action
timing experiments.
