import React from "react";
import base64 from "react-native-base64";
import * as API from "./apiCaller";

export class MessageView extends React.Component {
  constructor(props) {
    super(props);
    this.state = { msgId: window.location.pathname.split("/")[2], msgData: "" };
  }

  componentDidMount() {
    let self = this;
    API.callApi({ action: "message", "msg-id": self.state.msgId, type: "html" })
      .then(function (response) { // $ Source[js/xss]
        return response.json();
      })
      .then(function (data) {
        self.setState({ msgData: data.message });
      });
  }

  render() {
    return (
      <div>
        <h2>Message {this.state.msgId}</h2>
        {/* A `<script` blacklist does not stop event-handler or SVG payloads. */}
        <div dangerouslySetInnerHTML={{ __html: base64.decode(this.state.msgData).replace(/(<? *script)/gi, "illegalscript") }} /> {/* $ Alert[js/xss] */}
        <p>{base64.decode(this.state.msgData)}</p>
      </div>
    );
  }
}
