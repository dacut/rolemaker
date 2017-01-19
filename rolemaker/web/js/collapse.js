jQuery(function ($) {
    var on_hidden = function (ev) {
        var div = $(ev.currentTarget);
        var caret = div.attr("data-caret");
        if (caret) {
            $(caret).addClass("glyphicon-chevron-right");
            $(caret).removeClass("glyphicon-chevron-down");
        }
    };

    var on_shown = function (ev) {
        var div = $(ev.currentTarget);
        var caret = div.attr("data-caret");
        if (caret) {
            $(caret).addClass("glyphicon-chevron-down");
            $(caret).removeClass("glyphicon-chevron-right");
        }
    };

    $('.collapse').each(function () {
        $(this).on('hide.bs.collapse', on_hidden);
        $(this).on('show.bs.collapse', on_shown);
    });
});
