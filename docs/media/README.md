# Recording the demo GIF

`demo.gif` is a placeholder. The real demo shows **the thermostat keeping working in Home
Assistant after its cloud is shut down**. Record it with the simulators, so no real device or
vendor is involved:

1. Start a Home Assistant test instance and a broker (for example the `homeassistant` and
   `eclipse-mosquitto` containers), and point Modigliani Server's `home_assistant.broker` at it.
2. Record the thermostat against its cloud simulator, as the end-to-end suite does
   (`tests/e2e/conftest.py` shows the steps): `modigliani record --mode proxy ...`, set 22.5 °C
   and mode *cool* through the cloud simulator, and annotate each action.
3. `modigliani infer lab --device thermostat`.
4. Stop the cloud simulator. On screen, show that the vendor cloud is gone (connection refused).
5. Start `modigliani-server` with the profile and point the thermostat simulator at it.
6. In Home Assistant, open the thermostat card, change the target temperature and the mode, and
   show the simulator's state following.

Capture the screen at 12 to 15 frames per second, about 20 seconds, at most 900 px wide (for
example with ScreenToGif on Windows or Peek on Linux). Keep the file under 5 MB and replace
`docs/media/demo.gif`.
