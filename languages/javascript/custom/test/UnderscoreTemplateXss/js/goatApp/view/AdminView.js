define([
    'jquery',
    'backbone',
    'underscore',
    'goatApp/model/AdminModel',
    'text!templates/admin_panel.html'
], function ($, Backbone, _, AdminModel, AdminTemplate) {

    return Backbone.View.extend({

        el: '#admin-panel-page',
        template: AdminTemplate,

        initialize: function () {
            var _this = this;
            this.collection = new AdminModel();
            this.collection.fetch().then(function () {
                _this.render();
            });
        },

        render: function () {
            var t = _.template(this.template || AdminTemplate);
            this.$el.html(t({ users: this.collection.toJSON() })); // $ Source[js/underscore-template-xss]
            return this;
        }
    });
});
