define(['jquery', 'backbone', 'underscore', 'text!templates/profile.html', 'text!templates/banner.html'],
function ($, Backbone, _, ProfileTemplate, BannerTemplate) {

    return Backbone.View.extend({
        template: _.template(ProfileTemplate),
        banner: _.template(BannerTemplate),

        render: function () {
            this.$el.html(this.template(this.model.toJSON())); // $ Source[js/underscore-template-xss]
            // Constant data only: not reported.
            this.$el.append(this.banner({ title: 'Welcome' }));
            return this;
        }
    });
});
