# Odoo 18 IoT Driver Data Event Envelope

Date: 2026-06-22

## Purpose

This note records what `Driver.data` / `self.data` means in Odoo 18.0 IoT
drivers, how upstream code turns it into browser-visible events, and what that
means for the fiscal data module driver.

The immediate conclusion is:

- `self.data` is the driver's mutable event envelope;
- upstream `hw_drivers` copies the current `self.data` mapping into every
  emitted IoT event;
- `data["value"]` is upstream's generic scalar/current-reading/display channel,
  not a typed business payload channel;
- `/hw_posbox_homepage/data` assumes every IoT device has `data["value"]`;
- browser IoT listeners receive every key copied from `self.data`;
- fiscal result publication should extend the existing device envelope with
  `result`, not replace the envelope.

## Source-Proof Scope

This is source proof only. No Odoo server, browser session, IoT Box runtime,
database, fiscal printer, or hardware device was started.

Odoo source paths below are relative to the relevant Odoo 18.0 checkout root.
Odoo Community source was inspected at commit
[`0b23a1cd324bb33865f9a64e1d422209499db1a4`](https://github.com/odoo/odoo/tree/0b23a1cd324bb33865f9a64e1d422209499db1a4).
Odoo Enterprise source was inspected at commit
`56a65f3a355036126588faf5f6c4d24357e334f4`; because that source is
local/private provenance, this note records paths and findings rather than
machine-local links.

## Source Reference Convention

Odoo 18.0 Community source paths:

1. `odoo/addons/hw_drivers/driver.py`
2. `odoo/addons/hw_drivers/event_manager.py`
3. `odoo/addons/hw_drivers/controllers/driver.py`
4. `odoo/addons/hw_drivers/iot_handlers/drivers/PrinterDriver_W.py`
5. `odoo/addons/hw_drivers/iot_handlers/drivers/KeyboardUSBDriver_L.py`
6. `odoo/addons/hw_drivers/iot_handlers/drivers/SerialScaleDriver.py`
7. `odoo/addons/hw_posbox_homepage/controllers/homepage.py`

Odoo 18.0 Enterprise source paths:

1. `enterprise/iot/static/src/device_controller.js`
2. `enterprise/iot/static/src/iot_longpolling.js`
3. `enterprise/pos_iot/static/src/overrides/components/barcode_reader/barcode_reader.js`
4. `enterprise/pos_iot/static/src/overrides/components/scale_screen/scale_service.js`
5. `enterprise/iot/iot_handlers/lib/ctypes_terminal_driver.py`

Addon source paths:

1. `iot_handlers/drivers/CWFiscalModuleDriver_W.py`
2. `static/src/overrides/printer/iot_printer.js`
3. `static/src/overrides/helpers/fiscal_frontend_runtime.js`
4. `static/src/backend/fiscal_device_serialization_status.js`

## What `self.data` Is

The base Odoo IoT `Driver` initializes each device with:

```python
self.data = {'value': ''}
```

That default is not only for scanners or scales. It is the generic minimum
shape expected by at least one upstream page: `hw_posbox_homepage` renders every
device by reading `iot_devices[device].data['value']`.

Stock printer drivers add status by replacing `self.data` with a complete
status snapshot:

```python
self.data = {
    'value': '',
    'state': self.state,
}
event_manager.device_changed(self)
```

That replacement is safe for a status-only event because the driver is
publishing the whole event envelope it wants listeners to see at that moment.
It is not a general rule that every event producer should replace `self.data`.

## What Upstream Uses `value` For

Upstream uses `data["value"]` as a generic scalar field for the current or last
device value. It is intentionally broad, but upstream examples keep it as a
small displayable or directly consumable value:

- the base `Driver` initializes it to an empty string;
- `hw_posbox_homepage` stringifies it and displays it as the device value;
- keyboard/scanner drivers set it to a key character or completed barcode;
- POS IoT barcode code consumes listener payloads with `barcode.value`;
- scale drivers set it to a measured numeric weight;
- POS IoT scale code reads `data.value || data.result || 0`;
- payment terminal helpers may use it for short payment-terminal status or
  response values.

This makes `value` a generic IoT channel, not a fiscal result channel. A driver
can leave it empty when the device has no useful scalar reading. If a custom
driver wants a homepage-friendly value, it should be a short scalar summary,
not a nested evidence object.

## Upstream Event Flow

```text
[A] IoT Driver instance
    owns device.data
        |
        | event_manager.device_changed(device)
        v
[B] hw_drivers EventManager
    event = {**device.data, device_identifier, time, request_data}
        |
        +--> short in-memory replay list
        |
        +--> active /hw_drivers/event listener session
                 |
                 v
[C] enterprise/iot IoTLongpolling
    callback(result) for matching device_identifier
                 |
                 v
[D] POS/addon callback code
    reads result, state, value, request_data, etc. from one event object
```

The important coupling is at `[B]`: Odoo does a shallow copy of all current
`device.data` keys into the event. The browser callback does not receive a
typed status event or typed fiscal result event; it receives one JSON object
whose shape is whatever the driver left in `self.data`.

## Homepage Flow

```text
[IoT device registered in hw_drivers.main.iot_devices]
        |
        | GET /hw_posbox_homepage/data
        v
[hw_posbox_homepage controller]
        |
        | str(iot_devices[device].data['value'])
        v
[IoT homepage device list]
```

This page is independent of the fiscal POS event flow. A fiscal result can be
handled correctly by POS and still break the homepage if result publication
removed `data["value"]`.

## POS Listener Flow

```text
[POS DeviceController.addListener(callback)]
        |
        | iotLongpolling.addListener(iot_ip, [identifier], listener_id)
        v
[enterprise/iot listener map]
        |
        | POST /hw_drivers/event
        v
[IoT Box EventManager]
        |
        | returns copied event envelope
        v
[IoTLongpolling._onSuccess]
        |
        | devices[result.device_identifier].callback(result)
        v
[Fiscal addon callback]
        |
        | extracts payload.result when it is a private API fiscal result signal
        v
[POS fiscal waiter/staging/status code]
```

Current fiscal frontend consumers accept either a root fiscal result signal or a
nested `payload.result` signal. They do not need `state` to parse the fiscal
result, but they do receive any `state` key that the driver preserves in the
event envelope.

## Payload Placement Rule

```text
Is the emitted fact a generic scalar/current device reading?
  |
  +-- yes -> put the scalar in data["value"]
  |
  +-- no
        |
        | Is it a typed business/diagnostic envelope?
        |
        +-- yes -> put it under an explicit key, e.g. data["result"]
        |
        +-- no  -> keep value empty or use another explicit field
```

Setting `data["value"]` to a fiscal result object would make the homepage show
a large technical dictionary as "last sent value", and it would make generic
IoT listeners see a nested fiscal business envelope in a field that upstream
uses for scanner text, scale weight, payment status text, or an empty scalar.

The fiscal result already has a typed event location: `payload.result`. Keeping
the full fiscal result there avoids two competing meanings for one field.

## Safe Mutation Rule

```text
Status event
  -> driver may publish a complete status snapshot:
     data = {value, state}

Result event
  -> driver should add result to the existing envelope:
     data[value] remains present
     data[state] remains whatever status publisher last set
     data[result] becomes the fiscal result signal

Do not replace the whole envelope for an additive event.
```

For this fiscal driver, `send_status()` owns status publication. `_publish_result()`
owns the terminal fiscal result signal. Result publication must not delete the
generic `value` key, and should not accidentally delete status fields or other
future generic device fields.

The safe implementation shape is:

```python
self.data["value"] = self.data.get("value", "")
self.data["result"] = result
event_manager.device_changed(self)
```

This preserves upstream compatibility and keeps the fiscal result lean:

- `value` remains present for `hw_posbox_homepage`;
- `value` remains a scalar placeholder rather than duplicating the fiscal
  business envelope;
- existing `state` is preserved if the status publisher placed it there;
- `result` is updated for fiscal POS consumers;
- no retired `/iot/fiscal_result` callback path is reintroduced.

## Why Not Copy Upstream Replacement Blindly

The stock printer status methods replace `self.data` because they are producing
a complete status event. The fiscal result method is different: it is adding a
business result to an already registered generic IoT device envelope. Replacing
the mapping there is a lossy operation.

The safer local rule is:

- replace `self.data` only when the method owns the complete event shape being
  published;
- update `self.data` in place when publishing an additional payload dimension
  for the same device;
- always preserve `value` unless the upstream homepage contract changes.

## Regression Context

The regression came from changing `_publish_result()` from:

```python
self.data = {
    "value": "",
    "state": self.state,
    "result": result,
}
```

to:

```python
self.data = {
    "result": result,
}
```

That kept fiscal POS result consumption lean, but it removed the generic
`value` key required by `hw_posbox_homepage`. The corrected direction is not to
restore a hand-built full mapping in `_publish_result()`, but to keep the
driver envelope intact and update only the fiscal result field.

## Open Runtime Proof

A runtime check would require an Odoo IoT runtime with the fiscal module driver
loaded and a browser or HTTP client calling both:

- `/hw_posbox_homepage/data`;
- the POS IoT listener path for the fiscal device.

That was not run as part of this source-only discovery note.
