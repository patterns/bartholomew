//
// It returns an array of objects of the form:
//  [
//    #{ uri: "path/to/page", page: PageObject, sequence: int }
// ]

// Param 1 should be `site.pages`
let pages = params[0];

// Loop through them and return all of the page objects that are in
// the blurb path.

let tiles = #{
    cola: [],
    colb: [],
    colc: [],
};
let row = 0;
let col = 0;
let cursor = "";
//todo necessary to order pages at the start?

// Get each blurb post, assigning it to {path: object}.
let keys = pages.keys();
for item in keys {
    if item.index_of("/content/blurb/") != 0 { continue; }
    let matter = pages[item];
    let front = matter.head;
    let stamp = front.extra.date;
    let date_tag = stamp.split('T')[0];
    if cursor == date_tag {
        // day stayed the same, keep row increment column
        col = (col + 1) % 3;
    } else {
        row += 1;
        col = 0;
        cursor = date_tag;
    }


    // Remove /content and .md
    let path = item.sub_string(8);
    path = path.sub_string(0, path.index_of(".md"));

    let article = #{
            uri: path,
            page: matter,
            row: row,
            col: col,
    };

    switch col {
        0 => tiles.cola.push(article),
        1 => tiles.colb.push(article),
        2 => tiles.colc.push(article),
        _ => tiles.colc.push(article),
    }
}
// Newest to oldest, assuming you put the date in the URI
////blurb_pages.reverse();
tiles
