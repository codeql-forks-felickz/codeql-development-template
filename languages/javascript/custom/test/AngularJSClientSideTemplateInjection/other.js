// Loaded only from plain.html, which is not an AngularJS application.
var ref = document.location.hash.substring(1);
document.getElementById('message').innerText = ref;
