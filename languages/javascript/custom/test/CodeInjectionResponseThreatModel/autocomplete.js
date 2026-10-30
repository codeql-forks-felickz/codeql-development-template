(function ($) {
  var Autocomplete = function (serviceUrl) {
    this.serviceUrl = serviceUrl;
  };

  Autocomplete.prototype = {
    getSuggestions: function (q) {
      var me = this;
      $.get(this.serviceUrl, { query: q }, function (txt) { me.processResponse(txt); }, 'text');
    },

    processResponse: function (text) {
      // BAD: the server response is evaluated as code
      var response = eval('(' + text + ')');
      // GOOD: the server response is parsed as JSON
      var parsed = JSON.parse(text);
      return [response, parsed];
    }
  };

  $.fn.autocomplete = function (serviceUrl) {
    return new Autocomplete(serviceUrl);
  };
})(jQuery);
