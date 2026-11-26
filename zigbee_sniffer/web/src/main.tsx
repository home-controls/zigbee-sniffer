import { render } from "preact";
import { App } from "./App";
import { startStatus } from "./store";
import "./kit/tokens.css";
import "./kit/fonts-ha.css";
import "./kit/base.css";
import "./kit/zigbee.css";
import "./sniffer.css";

startStatus();
render(<App />, document.getElementById("app")!);
