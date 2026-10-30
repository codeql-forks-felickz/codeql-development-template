// Stored XSS: user names saved through an update endpoint are rendered from an XHR response.
function populateForm() {
  var xhr = new XMLHttpRequest();
  xhr.open("GET", "get_user_data.php", true);
  xhr.onreadystatechange = function () {
    if (this.readyState !== 4 || this.status !== 200) {
      return;
    }
    const users = JSON.parse(this.responseText); // $ Source[js/xss]
    const tableBody = document.getElementById("user_table").getElementsByTagName("tbody")[0];
    users.forEach(updateTable);

    function updateTable(user) {
      var row = tableBody.insertRow(0);
      var cell1 = row.insertCell(-1);
      // `insertRow`/`insertCell` are recognized as returning DOM elements through the browser
      // externs, which `codeql database create` extracts but qltest databases do not.
      cell1.innerHTML = '<input type="text" name="first_name" value="' + user["first_name"] + '" />'; // $ MISSING: Alert[js/xss]
      document.getElementById("surname_" + user["user_id"]).innerHTML = user["surname"]; // $ Alert[js/xss]
      // Safe: written as text.
      document.getElementById("id_" + user["user_id"]).innerText = user["first_name"];
    }
  };
  xhr.send();
}
