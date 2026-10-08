# Odoo 19 IoT Bidirectional Action Channel Source Research

## Purpose

This note records source-inspection findings about why Odoo 19.0 can support a
browser/PWA-owned queue for Belgian blackbox fiscal commands, and why the same
assumption must not be made for this Odoo 18.0 addon without an explicit
transport design.

The immediate architecture consequence for this addon is:

- the addon can rename its fiscal IoT action from `enqueue_request` to
  `execute_fiscal_command`;
- the addon should remove the local SQLite queue entirely;
- a future POS PWA durable queue is a separate design because Odoo 18.0 does
  not expose the same general POS-to-IoT bidirectional action channel that
  Odoo 19.0 uses.

## Research Scope

Target source versions:

- Odoo 19.0 Community `iot_drivers`
- Odoo 19.0 Enterprise `iot`
- Odoo 19.0 Enterprise `pos_blackbox_be`
- Odoo 18.0 Enterprise `iot`
- Odoo 18.0 Community `hw_drivers`

This is source proof only. No Odoo server, database, IoT Box, browser session,
or hardware runtime was started.

The Odoo source checkouts are local/private provenance. Paths below are paths
inside those checkouts, not durable hyperlinks.

## Odoo 19.0 Findings

Odoo 19.0 Enterprise `iot` defines a general POS/browser service for IoT
actions in:

```text
enterprise/iot/static/src/network_utils/iot_http_service.js
```

Relevant symbols:

- `IotHttpService.action(...)`
- `IotHttpService.onMessage(...)`
- `IotHttpService._webRtc(...)`
- `IotHttpService._longpolling(...)`
- `IotHttpService._websocket(...)`

`action(...)` assigns an `action_unique_id`, then attempts the configured
connection strategies. The websocket path sends the action payload and waits
for an `operation_confirmation` message keyed by the same message/session id.
The service therefore exposes one high-level browser API for bidirectional
IoT device actions, with WebRTC, longpolling, and websocket fallback behavior.

Odoo 19.0 Enterprise `iot` defines the browser websocket helper in:

```text
enterprise/iot/static/src/network_utils/iot_websocket.js
```

Relevant symbols:

- `IotWebsocket.sendMessage(...)`
- `IotWebsocket.onMessage(...)`

`sendMessage(...)` calls `iot.channel.send_message(...)` with message type
`iot_action` by default. `onMessage(...)` subscribes to
`operation_confirmation` by default, filters by IoT box identifier, device
identifier, and session id, then calls success or failure callbacks.

Odoo 19.0 Enterprise `iot` forwards IoT Box completion messages in:

```text
enterprise/iot/controllers/main.py
```

Relevant symbol:

- `IoTController.iot_box_send_websocket(...)`

The `/iot/box/send_websocket` route validates the IoT box and device, then
sends an `operation_confirmation` message on the IoT channel. The forwarded
message contains the original `session_id`, the IoT box identifier, the device
identifier, the status, result, and action arguments.

Odoo 19.0 Community `iot_drivers` runs the IoT Box-side websocket client in:

```text
odoo/addons/iot_drivers/websocket_client.py
```

Relevant symbols:

- `WebsocketClient.on_message(...)`
- `send_to_controller(...)`

`WebsocketClient.on_message(...)` receives `iot_action` messages, filters them
by the local IoT identifier, iterates `device_identifiers`, and calls
`main.iot_devices[device_identifier].action(payload)`. For unknown devices it
posts a disconnected response back to Odoo through `send_to_controller(...)`.

Odoo 19.0 Community `iot_drivers` provides the common driver action dispatcher
in:

```text
odoo/addons/iot_drivers/driver.py
```

Relevant symbol:

- `Driver.action(...)`

`Driver.action(...)` extracts the requested action key, deduplicates optional
`action_unique_id`, calls `self._actions[action](data)`, and produces a
response containing status, result, action arguments, and session id. For most
device types it sends the response through the event manager.

Odoo 19.0 Community `iot_drivers` publishes device action results in:

```text
odoo/addons/iot_drivers/event_manager.py
```

Relevant symbol:

- `EventManager.device_changed(...)`

`device_changed(...)` builds an event, calls `send_to_controller(...)` with the
IoT box identifier, optionally sends through WebRTC, appends the event to the
longpolling event list, and wakes matching longpolling listeners.

Odoo 19.0 Enterprise `pos_blackbox_be` uses this infrastructure from the POS
PWA in:

```text
enterprise/pos_blackbox_be/static/src/pos/app/services/blackbox_queue_service.js
```

Relevant symbols:

- `BlackboxQueueService.enqueue(...)`
- `BlackboxQueueService.flush(...)`
- `BlackboxQueueService.pushDataToBlackbox(...)`

The service persists queued blackbox requests in browser `localStorage`, then
flushes them through `this.iotHttp.action(...)`. The payload action sent to the
IoT driver is `batchAction`, and the service expects the callback from
`iot_http.action(...)` to resolve with blackbox responses that match the sent
batch order.

Odoo 19.0 Enterprise `pos_blackbox_be` implements the IoT driver side in:

```text
enterprise/pos_blackbox_be/iot_handlers/drivers/serial_blackbox_driver.py
```

Relevant symbols:

- `BlackBoxDriver._set_actions(...)`
- `BlackBoxDriver.supported(...)`
- `BlackBoxDriver._batch_action(...)`
- `BlackBoxDriver._send_to_blackbox(...)`

The driver registers `batchAction`, executes the batch synchronously against
the serial blackbox, and stores the response in `self.data['result']`. The
driver also actively probes the serial device in `supported(...)` by sending a
status request and expecting a valid response/ACK behavior.

## Odoo 18.0 Comparison

Odoo 18.0 Enterprise `iot` has websocket-related code, but the browser-facing
service inspected here is printer/report confirmation oriented rather than the
general Odoo 19.0 `iot_http.action(...)` abstraction.

The browser service inspected is:

```text
enterprise/iot/static/src/iot_websocket_service.js
```

Relevant symbols:

- `IotWebsocket.addJob(...)`
- `IotWebsocket.onPrintConfirmation(...)`
- `IotWebsocketService.start(...)`

This service tracks print jobs, subscribes to `print_confirmation`, and clears
print-job notifications when the matching printer confirmation arrives. It does
not expose the same general-purpose `action(...)` and `onMessage(...)` API used
by Odoo 19.0 POS IoT code.

The Odoo 18.0 Enterprise controller inspected is:

```text
enterprise/iot/controllers/main.py
```

Relevant symbol:

- `IoTController.listen_iot_printer_status(...)`

The `/iot/box/send_websocket` route is shared with `/iot/printer/status` and
forwards `print_confirmation` when `print_id`, IoT identifier, and device
identifier are present. The controller comment explicitly describes printer
operation acknowledgement, and the route ignores payloads that do not fit that
printer-confirmation shape.

Odoo 18.0 Community `hw_drivers` has an IoT Box-side websocket client in:

```text
odoo/addons/hw_drivers/websocket_client.py
```

Relevant symbols:

- `on_message(...)`
- `send_to_controller(...)`
- `WebsocketClient`

The client can receive `iot_action` messages and call
`main.iot_devices[device_identifier].action(payload)`, but its
`send_to_controller(...)` route map only covers printer status. This supports
the conclusion that the lower-level websocket pieces exist, while the Odoo
18.0 POS/browser and server confirmation layers do not provide the same
general bidirectional device-action contract as Odoo 19.0.

Odoo 18.0 Enterprise `pos_iot` source search found longpolling action usage
for local IoT actions, but not the Odoo 19.0 `iot_http.action(...)` service
with `operation_confirmation` semantics.

## Conclusions

The Odoo 19.0 POS PWA blackbox queue is viable because Odoo 19.0 provides a
general bidirectional POS/browser-to-IoT action channel:

```text
POS service
  -> iot_http.action(...)
  -> WebRTC / longpolling / websocket
  -> IoT Box websocket client
  -> Driver.action(...)
  -> EventManager.device_changed(...)
  -> /iot/box/send_websocket
  -> operation_confirmation
  -> POS success/failure callback
```

The Odoo 18.0 source inspected here does not provide that same complete
browser-facing abstraction. It has websocket and longpolling pieces, but the
durable, general-purpose action/confirmation API used by Odoo 19.0 is not
present in the inspected Odoo 18.0 POS IoT layer.

For the Curaçao fiscal addon targeting Odoo 18.0, this means:

1. Direct IoT-driver execution remains the accepted direction.
2. The fiscal action should be named `execute_fiscal_command`, not
   `enqueue_request`.
3. SQLite should not be retained to compensate for the missing Odoo 19.0
   browser queue infrastructure.
4. A future browser/PWA durable queue should be planned separately and should
   first define or backport the required bidirectional transport contract.
5. Implementation must stop if Odoo 18.0 cannot deliver the terminal result
   required by `execute_fiscal_command` over the accepted local IoT path.

## Source Proof Status

This document is source proof only. It identifies source files and symbols that
support the architecture conclusion, but it does not prove runtime behavior in
a configured Odoo database or browser session.
