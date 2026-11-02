// Reduced from a postMessage challenge page: user-entered values are sent to a
// popup window with an unrestricted target origin.
var window_ref = null;

function open_window() {
  if (window_ref == null || window_ref.closed) {
    window_ref = window.open("https://scoreboard.example.com/board.html", "score board");
  }
}

function send_message(message) {
  if (window_ref == null || window_ref.closed) {
    return;
  }
  window_ref.postMessage(message, "*"); // $ Alert
}

function send_message_restricted(message) {
  window_ref.postMessage(message, "https://scoreboard.example.com"); // OK: origin restricted
}

function send_message_to_self() {
  var input = document.querySelector("#comment");
  window.postMessage(input.value, "*"); // OK: the current window cannot expose its data cross-origin
}

function check_guess() {
  var guess = document.getElementById("guess").value;
  send_message("guess:" + guess);
  send_message_restricted("guess:" + guess);
}

function notify_ready() {
  // OK: constant, non-user data
  window_ref.postMessage("ready", "*");
}

function send_selection(frame) {
  var input = document.querySelector("#comment");
  frame.contentWindow.postMessage({ comment: input.value }, "*"); // $ Alert
}

document.getElementById("checkGuess").addEventListener("click", check_guess, false);
open_window();
