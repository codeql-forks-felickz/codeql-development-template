// API suggestions are inserted as markup, while the text-only counterpart is safe.
$.get("/api/suggestions", function (suggestions) { // $ Source[js/xss]
  suggestions.forEach(function (suggestion) {
    $("#suggestions").append('<li title="' + suggestion.label + '">' + suggestion.label + '</li>'); // $ Alert[js/xss]
    $("#safe-suggestions").text(suggestion.label);
  });
});
