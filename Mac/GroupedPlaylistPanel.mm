//
//  GroupedPlaylistPanel.mm
//  foo_sample
//
//  Functional NSTableView playlist with album grouping and album art
//  Shows actual playlist data from foobar2000
//

#import "stdafx.h"
#import "GroupedPlaylistPanel.h"
#import <vector>
#import <string>
#import <map>
#import <set>
#import <mutex>
#import <memory>
#import <functional>
#import <algorithm>

#pragma mark - Data Model

// Column definition for customizable columns
struct ColumnDef {
    std::string identifier;      // Unique ID
    std::string title;           // Display title
    std::string titleformat;     // Titleformat pattern (e.g., "%artist%", "%codec%")
    CGFloat width;               // Column width
    CGFloat minWidth;            // Minimum width
    NSTextAlignment alignment;   // Text alignment
    bool visible;                // Whether column is shown
    bool isBuiltIn;              // Built-in columns can't be removed
};

// Available column templates
static std::vector<ColumnDef> GetAvailableColumns() {
    return {
        {"playing",    "",           "",                    24,  24, NSTextAlignmentCenter, true,  true},
        {"trackNo",    "#",          "%tracknumber%",       40,  30, NSTextAlignmentRight,  true,  true},
        {"title",      "Title",      "%title%",            200, 100, NSTextAlignmentLeft,   true,  true},
        {"artist",     "Artist",     "%artist%",           150,  80, NSTextAlignmentLeft,   true,  false},
        {"album",      "Album",      "%album%",            150,  80, NSTextAlignmentLeft,   true,  false},
        {"duration",   "Duration",   "%length%",            60,  50, NSTextAlignmentRight,  true,  false},
        {"codec",      "Codec",      "%codec%",             60,  40, NSTextAlignmentLeft,   false, false},
        {"bitrate",    "Bitrate",    "%bitrate% kbps",      80,  60, NSTextAlignmentRight,  false, false},
        {"samplerate", "Sample Rate","%samplerate% Hz",     80,  60, NSTextAlignmentRight,  false, false},
        {"channels",   "Channels",   "%channels%",          60,  40, NSTextAlignmentCenter, false, false},
        {"playcount",  "Plays",      "%play_count%",        50,  40, NSTextAlignmentRight,  false, false},
        {"rating",     "Rating",     "%rating%",            60,  40, NSTextAlignmentCenter, false, false},
        {"genre",      "Genre",      "%genre%",            100,  60, NSTextAlignmentLeft,   false, false},
        {"year",       "Year",       "%date%",              50,  40, NSTextAlignmentCenter, false, false},
        {"composer",   "Composer",   "%composer%",         120,  80, NSTextAlignmentLeft,   false, false},
        {"comment",    "Comment",    "%comment%",          150,  80, NSTextAlignmentLeft,   false, false},
        {"path",       "Path",       "%path%",             200, 100, NSTextAlignmentLeft,   false, false},
        {"filename",   "Filename",   "%filename%",         150,  80, NSTextAlignmentLeft,   false, false},
        {"filesize",   "Size",       "%filesize_natural%",  70,  50, NSTextAlignmentRight,  false, false},
        {"lastplayed", "Last Played","%last_played%",      120,  80, NSTextAlignmentLeft,   false, false},
        {"added",      "Date Added", "%added%",            120,  80, NSTextAlignmentLeft,   false, false},
    };
}

// Track data from playlist - now stores formatted values per column
struct TrackData {
    std::map<std::string, std::string> columnValues;  // Column ID -> formatted value
    size_t playlistIndex;  // Index in the actual playlist
    metadb_handle_ptr handle;  // Reference to track for playback/art
    std::string album;  // Keep album for grouping
};

// Row can be either a group header or a track
struct PlaylistRow {
    bool isGroupHeader;
    size_t dataIndex;      // Index into tracks array (for tracks)
    std::string albumName; // Album name (for group headers)
    NSImage* albumArt;     // Cached album art image
    NSColor* albumColor;   // Fallback color if no art
};

#pragma mark - Panel tracking for callbacks

static std::vector<__weak GroupedPlaylistPanel*> g_panels;
static std::mutex g_panels_mutex;

#pragma mark - Album Colors (fallback when no art)

static NSColor* GetAlbumColor(const std::string& album) {
    // Generate consistent color from album name hash
    size_t hash = std::hash<std::string>{}(album);
    return [NSColor colorWithRed:((hash >> 16) & 0xFF) / 255.0
                           green:((hash >> 8) & 0xFF) / 255.0
                            blue:(hash & 0xFF) / 255.0
                           alpha:1.0];
}

#pragma mark - Helper: Format duration

static std::string FormatDuration(double seconds) {
    if (seconds <= 0) return "";
    int mins = (int)(seconds / 60);
    int secs = (int)seconds % 60;
    char buf[32];
    snprintf(buf, sizeof(buf), "%d:%02d", mins, secs);
    return buf;
}

#pragma mark - Custom Table View for Keyboard Events

@implementation PlaylistTableView

- (void)keyDown:(NSEvent *)event {
    NSString *chars = event.charactersIgnoringModifiers;
    unichar key = chars.length > 0 ? [chars characterAtIndex:0] : 0;

    if (key == NSCarriageReturnCharacter || key == NSEnterCharacter) {
        // Enter/Return: Play selected track
        if (_playlistPanel) {
            [_playlistPanel playSelectedTrack];
        }
        return;
    } else if (key == NSDeleteCharacter || key == NSBackspaceCharacter) {
        // Delete/Backspace: Remove selected tracks
        if (_playlistPanel) {
            [_playlistPanel deleteSelectedTracks];
        }
        return;
    }

    [super keyDown:event];
}

- (BOOL)acceptsFirstResponder {
    return YES;
}

@end

#pragma mark - Album Art Cell View

@interface AlbumArtCellView : NSTableCellView
@property (nonatomic, strong) NSImageView *artImageView;
@property (nonatomic, strong) NSView *colorView;
@end

@implementation AlbumArtCellView

- (instancetype)initWithFrame:(NSRect)frameRect {
    self = [super initWithFrame:frameRect];
    if (self) {
        // Color fallback view
        _colorView = [[NSView alloc] initWithFrame:NSZeroRect];
        _colorView.wantsLayer = YES;
        _colorView.layer.cornerRadius = 4;
        _colorView.translatesAutoresizingMaskIntoConstraints = NO;
        [self addSubview:_colorView];

        // Image view on top
        _artImageView = [[NSImageView alloc] initWithFrame:NSZeroRect];
        _artImageView.imageScaling = NSImageScaleProportionallyUpOrDown;
        _artImageView.wantsLayer = YES;
        _artImageView.layer.cornerRadius = 4;
        _artImageView.layer.masksToBounds = YES;
        _artImageView.translatesAutoresizingMaskIntoConstraints = NO;
        [self addSubview:_artImageView];

        [NSLayoutConstraint activateConstraints:@[
            [_colorView.centerXAnchor constraintEqualToAnchor:self.centerXAnchor],
            [_colorView.centerYAnchor constraintEqualToAnchor:self.centerYAnchor],
            [_colorView.widthAnchor constraintEqualToConstant:32],
            [_colorView.heightAnchor constraintEqualToConstant:32],

            [_artImageView.centerXAnchor constraintEqualToAnchor:self.centerXAnchor],
            [_artImageView.centerYAnchor constraintEqualToAnchor:self.centerYAnchor],
            [_artImageView.widthAnchor constraintEqualToConstant:32],
            [_artImageView.heightAnchor constraintEqualToConstant:32]
        ]];
    }
    return self;
}

- (void)setAlbumArt:(NSImage *)image fallbackColor:(NSColor *)color {
    if (image) {
        _artImageView.image = image;
        _artImageView.hidden = NO;
        _colorView.hidden = YES;
    } else {
        _artImageView.image = nil;
        _artImageView.hidden = YES;
        _colorView.hidden = NO;
        _colorView.layer.backgroundColor = color.CGColor;
        _colorView.layer.borderWidth = 1;
        _colorView.layer.borderColor = [[color blendedColorWithFraction:0.5 ofColor:[NSColor blackColor]] CGColor];
    }
}

@end

#pragma mark - Group Header Cell View

@interface GroupHeaderCellView : NSTableCellView
@property (nonatomic, strong) NSImageView *artImageView;
@property (nonatomic, strong) NSView *colorView;
@property (nonatomic, strong) NSTextField *albumLabel;
@property (nonatomic, strong) NSTextField *trackCountLabel;
@end

@implementation GroupHeaderCellView

- (instancetype)initWithFrame:(NSRect)frameRect {
    self = [super initWithFrame:frameRect];
    if (self) {
        // Allow content to extend beyond cell bounds
        self.wantsLayer = YES;
        self.layer.masksToBounds = NO;

        // Color fallback
        _colorView = [[NSView alloc] initWithFrame:NSZeroRect];
        _colorView.wantsLayer = YES;
        _colorView.layer.cornerRadius = 6;
        _colorView.translatesAutoresizingMaskIntoConstraints = NO;
        [self addSubview:_colorView];

        // Album art image
        _artImageView = [[NSImageView alloc] initWithFrame:NSZeroRect];
        _artImageView.imageScaling = NSImageScaleProportionallyUpOrDown;
        _artImageView.wantsLayer = YES;
        _artImageView.layer.cornerRadius = 6;
        _artImageView.layer.masksToBounds = YES;
        _artImageView.translatesAutoresizingMaskIntoConstraints = NO;
        [self addSubview:_artImageView];

        // Album name label
        _albumLabel = [[NSTextField alloc] initWithFrame:NSZeroRect];
        _albumLabel.bordered = NO;
        _albumLabel.editable = NO;
        _albumLabel.selectable = NO;
        _albumLabel.backgroundColor = [NSColor clearColor];
        _albumLabel.font = [NSFont boldSystemFontOfSize:14];
        _albumLabel.textColor = [NSColor labelColor];
        _albumLabel.lineBreakMode = NSLineBreakByTruncatingTail;
        _albumLabel.translatesAutoresizingMaskIntoConstraints = NO;
        [self addSubview:_albumLabel];

        // Track count label
        _trackCountLabel = [[NSTextField alloc] initWithFrame:NSZeroRect];
        _trackCountLabel.bordered = NO;
        _trackCountLabel.editable = NO;
        _trackCountLabel.selectable = NO;
        _trackCountLabel.backgroundColor = [NSColor clearColor];
        _trackCountLabel.font = [NSFont systemFontOfSize:11];
        _trackCountLabel.textColor = [NSColor secondaryLabelColor];
        _trackCountLabel.translatesAutoresizingMaskIntoConstraints = NO;
        [self addSubview:_trackCountLabel];

        [NSLayoutConstraint activateConstraints:@[
            [_colorView.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:8],
            [_colorView.centerYAnchor constraintEqualToAnchor:self.centerYAnchor],
            [_colorView.widthAnchor constraintEqualToConstant:44],
            [_colorView.heightAnchor constraintEqualToConstant:44],

            [_artImageView.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:8],
            [_artImageView.centerYAnchor constraintEqualToAnchor:self.centerYAnchor],
            [_artImageView.widthAnchor constraintEqualToConstant:44],
            [_artImageView.heightAnchor constraintEqualToConstant:44],

            [_albumLabel.leadingAnchor constraintEqualToAnchor:_artImageView.trailingAnchor constant:12],
            [_albumLabel.topAnchor constraintEqualToAnchor:self.centerYAnchor constant:-12],
            [_albumLabel.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-8],

            [_trackCountLabel.leadingAnchor constraintEqualToAnchor:_artImageView.trailingAnchor constant:12],
            [_trackCountLabel.topAnchor constraintEqualToAnchor:_albumLabel.bottomAnchor constant:2],
            [_trackCountLabel.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-8]
        ]];
    }
    return self;
}

- (void)setAlbumName:(NSString *)name trackCount:(NSInteger)count art:(NSImage *)image fallbackColor:(NSColor *)color {
    _albumLabel.stringValue = name ?: @"Unknown Album";
    _trackCountLabel.stringValue = [NSString stringWithFormat:@"%ld track%@", (long)count, count == 1 ? @"" : @"s"];

    if (image) {
        _artImageView.image = image;
        _artImageView.hidden = NO;
        _colorView.hidden = YES;
    } else {
        _artImageView.image = nil;
        _artImageView.hidden = YES;
        _colorView.hidden = NO;
        _colorView.layer.backgroundColor = color.CGColor;
        _colorView.layer.borderWidth = 1;
        _colorView.layer.borderColor = [[color blendedColorWithFraction:0.5 ofColor:[NSColor blackColor]] CGColor];
    }
}

@end

#pragma mark - GroupedPlaylistPanel Implementation

// Drag-and-drop pasteboard type
static NSPasteboardType const kPlaylistRowPasteboardType = @"com.foobar2000.playlist.row";

@interface GroupedPlaylistPanel ()
@property (nonatomic, strong) PlaylistTableView *tableView;
@property (nonatomic, strong) NSTextField *titleLabel;
@property (nonatomic) std::vector<TrackData> tracks;
@property (nonatomic) std::vector<PlaylistRow> rows;
@property (nonatomic) std::vector<ColumnDef> columns;  // Active column configuration
@property (nonatomic) std::map<std::string, NSImage*> albumArtCache;
@property (nonatomic) std::map<std::string, size_t> albumTrackCounts;
@property (nonatomic) size_t playingIndex;  // Currently playing track index
@end

@implementation GroupedPlaylistPanel

- (instancetype)init {
    self = [super initWithNibName:nil bundle:nil];
    if (self) {
        _playingIndex = SIZE_MAX;

        // Initialize with default visible columns
        auto allColumns = GetAvailableColumns();
        for (const auto& col : allColumns) {
            if (col.visible) {
                _columns.push_back(col);
            }
        }

        // Register for callbacks
        std::lock_guard<std::mutex> lock(g_panels_mutex);
        g_panels.push_back(self);
    }
    return self;
}

- (void)dealloc {
    // Unregister from callbacks
    std::lock_guard<std::mutex> lock(g_panels_mutex);
    g_panels.erase(
        std::remove_if(g_panels.begin(), g_panels.end(),
            [self](GroupedPlaylistPanel* p) { return p == nil || p == self; }),
        g_panels.end()
    );
}

- (void)loadView {
    NSView *containerView = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 500, 400)];
    containerView.wantsLayer = YES;
    self.view = containerView;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [self setupUI];
    [self reloadPlaylistData];
}

- (void)setupUI {
    // Title label
    _titleLabel = [[NSTextField alloc] initWithFrame:NSZeroRect];
    _titleLabel.stringValue = @"Playlist";
    _titleLabel.font = [NSFont boldSystemFontOfSize:16];
    _titleLabel.bordered = NO;
    _titleLabel.editable = NO;
    _titleLabel.selectable = NO;
    _titleLabel.backgroundColor = [NSColor clearColor];
    _titleLabel.textColor = [NSColor labelColor];
    _titleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_titleLabel];

    // Scroll view for table
    NSScrollView *scrollView = [[NSScrollView alloc] initWithFrame:NSZeroRect];
    scrollView.hasVerticalScroller = YES;
    scrollView.hasHorizontalScroller = NO;
    scrollView.autohidesScrollers = YES;
    scrollView.borderType = NSBezelBorder;
    scrollView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:scrollView];

    // Table view (custom subclass for keyboard handling)
    _tableView = [[PlaylistTableView alloc] initWithFrame:NSZeroRect];
    _tableView.playlistPanel = self;
    _tableView.dataSource = self;
    _tableView.delegate = self;
    _tableView.rowHeight = 36;
    _tableView.intercellSpacing = NSMakeSize(0, 0);
    _tableView.selectionHighlightStyle = NSTableViewSelectionHighlightStyleRegular;
    _tableView.allowsMultipleSelection = YES;
    _tableView.usesAlternatingRowBackgroundColors = YES;
    _tableView.doubleAction = @selector(tableViewDoubleClick:);
    _tableView.target = self;

    // Enable drag-and-drop
    [_tableView registerForDraggedTypes:@[kPlaylistRowPasteboardType, NSPasteboardTypeFileURL]];
    _tableView.draggingDestinationFeedbackStyle = NSTableViewDraggingDestinationFeedbackStyleGap;

    // Context menu for rows
    NSMenu *contextMenu = [[NSMenu alloc] initWithTitle:@"Playlist"];
    [contextMenu addItemWithTitle:@"Play" action:@selector(contextMenuPlay:) keyEquivalent:@""];
    [contextMenu addItem:[NSMenuItem separatorItem]];
    [contextMenu addItemWithTitle:@"Remove" action:@selector(contextMenuRemove:) keyEquivalent:@""];
    [contextMenu addItem:[NSMenuItem separatorItem]];
    [contextMenu addItemWithTitle:@"Select All" action:@selector(contextMenuSelectAll:) keyEquivalent:@""];
    _tableView.menu = contextMenu;

    // Add columns from configuration
    [self rebuildTableColumns];

    // Header context menu for column customization
    NSMenu *headerMenu = [[NSMenu alloc] initWithTitle:@"Columns"];
    [headerMenu setDelegate:(id<NSMenuDelegate>)self];
    _tableView.headerView.menu = headerMenu;

    scrollView.documentView = _tableView;

    // Layout constraints
    [NSLayoutConstraint activateConstraints:@[
        [_titleLabel.topAnchor constraintEqualToAnchor:self.view.topAnchor constant:12],
        [_titleLabel.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:12],
        [_titleLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-12],

        [scrollView.topAnchor constraintEqualToAnchor:_titleLabel.bottomAnchor constant:8],
        [scrollView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:12],
        [scrollView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-12],
        [scrollView.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor constant:-12],
    ]];
}

#pragma mark - Column Management

- (void)rebuildTableColumns {
    // Remove all existing columns
    while (_tableView.tableColumns.count > 0) {
        [_tableView removeTableColumn:_tableView.tableColumns.lastObject];
    }

    // Add columns from configuration
    for (const auto& col : _columns) {
        NSTableColumn *column = [[NSTableColumn alloc] initWithIdentifier:
            [NSString stringWithUTF8String:col.identifier.c_str()]];
        column.title = [NSString stringWithUTF8String:col.title.c_str()];
        column.width = col.width;
        column.minWidth = col.minWidth;

        // Playing column is fixed width
        if (col.identifier == "playing") {
            column.maxWidth = col.width;
        }

        [_tableView addTableColumn:column];
    }
}

- (void)addColumnWithIdentifier:(NSString *)identifier {
    std::string idStr = identifier.UTF8String;

    // Check if already added
    for (const auto& col : _columns) {
        if (col.identifier == idStr) return;
    }

    // Find in available columns
    auto available = GetAvailableColumns();
    for (auto& col : available) {
        if (col.identifier == idStr) {
            col.visible = true;
            _columns.push_back(col);
            [self rebuildTableColumns];
            [self reloadPlaylistData];  // Reload to get new column data
            return;
        }
    }
}

- (void)removeColumnWithIdentifier:(NSString *)identifier {
    std::string idStr = identifier.UTF8String;

    // Find and remove
    for (auto it = _columns.begin(); it != _columns.end(); ++it) {
        if (it->identifier == idStr && !it->isBuiltIn) {
            _columns.erase(it);
            [self rebuildTableColumns];
            [self.tableView reloadData];
            return;
        }
    }
}

- (BOOL)isColumnVisible:(NSString *)identifier {
    std::string idStr = identifier.UTF8String;
    for (const auto& col : _columns) {
        if (col.identifier == idStr) return YES;
    }
    return NO;
}

#pragma mark - Header Menu Delegate (Column Customization)

- (void)menuNeedsUpdate:(NSMenu *)menu {
    if (menu != _tableView.headerView.menu) return;

    [menu removeAllItems];

    // Add all available columns as menu items
    auto available = GetAvailableColumns();
    for (const auto& col : available) {
        if (col.identifier == "playing") continue;  // Don't show playing column option

        NSString *identifier = [NSString stringWithUTF8String:col.identifier.c_str()];
        NSString *title = [NSString stringWithUTF8String:col.title.c_str()];

        NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title
                                                      action:@selector(toggleColumn:)
                                               keyEquivalent:@""];
        item.representedObject = identifier;
        item.state = [self isColumnVisible:identifier] ? NSControlStateValueOn : NSControlStateValueOff;

        // Mark built-in columns that can't be removed
        if (col.isBuiltIn && [self isColumnVisible:identifier]) {
            item.enabled = NO;  // Can't remove built-in visible columns
        }

        [menu addItem:item];
    }
}

- (void)toggleColumn:(NSMenuItem *)sender {
    NSString *identifier = sender.representedObject;
    if ([self isColumnVisible:identifier]) {
        [self removeColumnWithIdentifier:identifier];
    } else {
        [self addColumnWithIdentifier:identifier];
    }
}

#pragma mark - Playlist Data Loading

- (void)reloadPlaylistData {
    @try {
        try {
            auto pm = playlist_manager::get();
            if (!pm.is_valid()) return;

            // Get active playlist
            t_size activePlaylist = pm->get_active_playlist();
            if (activePlaylist == pfc::infinite_size) {
                activePlaylist = pm->get_playing_playlist();
            }
            if (activePlaylist == pfc::infinite_size || pm->get_playlist_count() == 0) {
                _tracks.clear();
                _rows.clear();
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.titleLabel.stringValue = @"No Playlist";
                    [self.tableView reloadData];
                });
                return;
            }

            // Get playlist name
            pfc::string8 playlistName;
            pm->playlist_get_name(activePlaylist, playlistName);

            // Get currently playing item
            t_size playingPlaylist, playingItem;
            bool hasPlaying = pm->get_playing_item_location(&playingPlaylist, &playingItem);
            if (!hasPlaying || playingPlaylist != activePlaylist) {
                playingItem = pfc::infinite_size;
            }

            // Get track count
            t_size itemCount = pm->playlist_get_item_count(activePlaylist);

            // Compile titleformat scripts for each column
            auto tfc = titleformat_compiler::get();
            std::map<std::string, titleformat_object::ptr> scripts;

            if (tfc.is_valid()) {
                for (const auto& col : _columns) {
                    if (!col.titleformat.empty()) {
                        titleformat_object::ptr script;
                        tfc->compile_safe_ex(script, col.titleformat.c_str());
                        scripts[col.identifier] = script;
                    }
                }
                // Always compile album for grouping
                if (scripts.find("album") == scripts.end()) {
                    titleformat_object::ptr albumScript;
                    tfc->compile_safe_ex(albumScript, "%album%");
                    scripts["album"] = albumScript;
                }
            }

            // Load tracks
            std::vector<TrackData> newTracks;
            newTracks.reserve(itemCount);

            for (t_size i = 0; i < itemCount; i++) {
                metadb_handle_ptr handle;
                if (!pm->playlist_get_item_handle(handle, activePlaylist, i)) continue;

                TrackData track;
                track.playlistIndex = i;
                track.handle = handle;

                // Get metadata using titleformat for each column
                pfc::string8 text;

                for (const auto& script : scripts) {
                    if (script.second.is_valid()) {
                        pm->playlist_item_format_title(activePlaylist, i, nullptr, text,
                                                       script.second, nullptr,
                                                       playback_control::display_level_none);
                        track.columnValues[script.first] = text.c_str();
                    }
                }

                // Store album for grouping
                auto albumIt = track.columnValues.find("album");
                if (albumIt != track.columnValues.end()) {
                    track.album = albumIt->second;
                }
                if (track.album.empty()) {
                    track.album = "(Unknown Album)";
                    track.columnValues["album"] = track.album;
                }

                // Default title if empty
                auto titleIt = track.columnValues.find("title");
                if (titleIt == track.columnValues.end() || titleIt->second.empty()) {
                    track.columnValues["title"] = "(Unknown Title)";
                }

                newTracks.push_back(track);
            }

            // Update on main thread
            NSString *nsPlaylistName = [NSString stringWithUTF8String:playlistName.c_str()];
            size_t nsPlayingItem = playingItem;

            dispatch_async(dispatch_get_main_queue(), ^{
                self.tracks = std::move(newTracks);
                self.playingIndex = nsPlayingItem;
                self.titleLabel.stringValue = [NSString stringWithFormat:@"%@ (%zu tracks)", nsPlaylistName, self.tracks.size()];
                [self buildRowsWithGrouping];
                [self.tableView reloadData];
                [self loadAlbumArtAsync];
            });

        } catch (const std::exception& e) {
            NSLog(@"GroupedPlaylistPanel: Exception loading playlist: %s", e.what());
        } catch (...) {
            NSLog(@"GroupedPlaylistPanel: Unknown exception loading playlist");
        }
    } @catch (NSException *exception) {
        NSLog(@"GroupedPlaylistPanel: NSException: %@", exception);
    }
}

- (void)buildRowsWithGrouping {
    _rows.clear();
    _albumTrackCounts.clear();

    if (_tracks.empty()) return;

    // First pass: count tracks per album
    for (const auto& track : _tracks) {
        _albumTrackCounts[track.album]++;
    }

    std::string currentAlbum;

    for (size_t i = 0; i < _tracks.size(); i++) {
        const TrackData& track = _tracks[i];

        // Insert group header when album changes
        if (track.album != currentAlbum) {
            currentAlbum = track.album;

            PlaylistRow header;
            header.isGroupHeader = true;
            header.dataIndex = i;
            header.albumName = track.album;
            header.albumColor = GetAlbumColor(track.album);
            header.albumArt = nil;

            // Check cache for album art
            auto artIt = _albumArtCache.find(track.album);
            if (artIt != _albumArtCache.end()) {
                header.albumArt = artIt->second;
            }

            _rows.push_back(header);
        }

        // Add track row
        PlaylistRow row;
        row.isGroupHeader = false;
        row.dataIndex = i;
        row.albumName = track.album;
        row.albumColor = GetAlbumColor(track.album);

        auto artIt = _albumArtCache.find(track.album);
        row.albumArt = (artIt != _albumArtCache.end()) ? artIt->second : nil;

        _rows.push_back(row);
    }
}

#pragma mark - Album Art Loading

- (void)loadAlbumArtAsync {
    // Load album art in background
    // Note: We need to capture track info for background processing, but update cache on main thread

    // First, collect albums that need art loading (on main thread where tracks are safe to access)
    std::vector<std::pair<std::string, metadb_handle_ptr>> albumsToLoad;
    std::set<std::string> processedAlbums;

    for (const auto& track : _tracks) {
        if (processedAlbums.count(track.album)) continue;
        processedAlbums.insert(track.album);

        // Check if already cached
        if (_albumArtCache.count(track.album)) continue;

        if (track.handle.is_valid()) {
            albumsToLoad.push_back({track.album, track.handle});
        }
    }

    if (albumsToLoad.empty()) return;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @try {
            try {
                for (const auto& albumPair : albumsToLoad) {
                    const std::string& albumKey = albumPair.first;
                    const metadb_handle_ptr& handle = albumPair.second;

                    // Try to get album art
                    NSImage *art = [self loadAlbumArtForHandle:handle];

                    if (art) {
                        // Store in cache and rebuild on main thread
                        std::string capturedAlbumKey = albumKey;
                        dispatch_async(dispatch_get_main_queue(), ^{
                            // Store directly in ivar, not via property
                            self->_albumArtCache[capturedAlbumKey] = art;

                            // Rebuild rows to pick up the cached art
                            [self buildRowsWithGrouping];
                            [self.tableView reloadData];
                        });
                    }
                }
            } catch (...) {
                NSLog(@"GroupedPlaylistPanel: Exception loading album art");
            }
        } @catch (NSException *e) {
            NSLog(@"GroupedPlaylistPanel: NSException loading album art: %@", e);
        }
    });
}

- (NSImage *)loadAlbumArtForHandle:(metadb_handle_ptr)handle {
    @try {
        try {
            if (!handle.is_valid()) return nil;

            abort_callback_dummy abort;

            auto path = handle->get_path();
            if (!path || !album_art_extractor::g_is_supported_path(path)) return nil;

            auto extractor = album_art_extractor::g_open_allowempty(nullptr, path, abort);
            if (!extractor.is_valid()) return nil;

            album_art_data_ptr artData;
            if (!extractor->query(album_art_ids::cover_front, artData, abort)) return nil;
            if (!artData.is_valid() || artData->get_size() == 0) return nil;

            // Try direct NSImage init first (simpler approach)
            NSData *data = [NSData dataWithBytes:artData->get_ptr() length:artData->get_size()];
            NSImage *image = [[NSImage alloc] initWithData:data];
            if (image) return image;

            // Fallback to fb2k::imageCreator
            auto img = fb2k::imageCreator::get()->loadImageData(
                artData->get_ptr(), artData->get_size());
            if (!img.is_valid()) return nil;

            // Get native NSImage from fb2k::image
            NSImage *nativeImage = (__bridge NSImage*)img->getNative();
            if (!nativeImage) return nil;

            return [nativeImage copy];

        } catch (const exception_album_art_not_found&) {
            return nil;
        } catch (...) {
            return nil;
        }
    } @catch (NSException *e) {
        return nil;
    }
}

#pragma mark - Double-click to play

- (void)tableViewDoubleClick:(id)sender {
    NSInteger row = _tableView.clickedRow;
    if (row < 0 || row >= (NSInteger)_rows.size()) return;

    const PlaylistRow& playlistRow = _rows[row];
    if (playlistRow.isGroupHeader) return;  // Don't play group headers

    const TrackData& track = _tracks[playlistRow.dataIndex];

    @try {
        try {
            auto pm = playlist_manager::get();
            if (!pm.is_valid()) return;

            t_size activePlaylist = pm->get_active_playlist();
            if (activePlaylist == pfc::infinite_size) return;

            // Execute default action (play) on the track
            pm->playlist_execute_default_action(activePlaylist, track.playlistIndex);

        } catch (const std::exception& e) {
            NSLog(@"GroupedPlaylistPanel: Exception playing track: %s", e.what());
        } catch (...) {
            NSLog(@"GroupedPlaylistPanel: Unknown exception playing track");
        }
    } @catch (NSException *e) {
        NSLog(@"GroupedPlaylistPanel: NSException playing track: %@", e);
    }
}

#pragma mark - NSTableViewDataSource

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView {
    return (NSInteger)_rows.size();
}

#pragma mark - NSTableViewDelegate

- (CGFloat)tableView:(NSTableView *)tableView heightOfRow:(NSInteger)row {
    if (row >= 0 && row < (NSInteger)_rows.size()) {
        if (_rows[row].isGroupHeader) {
            return 56;  // Taller row for group headers
        }
    }
    return 36;  // Normal row height
}

- (BOOL)tableView:(NSTableView *)tableView isGroupRow:(NSInteger)row {
    // Don't use NSTableView's built-in group row styling - we handle it ourselves
    // because isGroupRow causes NSTableView to use a different rendering path
    // that doesn't call viewForTableColumn:row: for all columns
    return NO;
}

- (BOOL)tableView:(NSTableView *)tableView shouldSelectRow:(NSInteger)row {
    if (row >= 0 && row < (NSInteger)_rows.size()) {
        return !_rows[row].isGroupHeader;
    }
    return YES;
}

- (NSTableRowView *)tableView:(NSTableView *)tableView rowViewForRow:(NSInteger)row {
    if (row >= 0 && row < (NSInteger)_rows.size() && _rows[row].isGroupHeader) {
        // For group headers, create a custom row view that will contain our header content
        NSTableRowView *rowView = [[NSTableRowView alloc] init];
        rowView.identifier = @"GroupHeaderRow";

        const PlaylistRow& playlistRow = _rows[row];

        // Create the group header content view
        GroupHeaderCellView *headerView = [[GroupHeaderCellView alloc] initWithFrame:NSZeroRect];
        headerView.translatesAutoresizingMaskIntoConstraints = NO;

        NSString *albumName = [NSString stringWithUTF8String:playlistRow.albumName.c_str()];
        NSInteger trackCount = _albumTrackCounts[playlistRow.albumName];

        // Check cache for album art
        NSImage *art = playlistRow.albumArt;
        if (!art) {
            auto artIt = _albumArtCache.find(playlistRow.albumName);
            if (artIt != _albumArtCache.end()) {
                art = artIt->second;
            }
        }

        [headerView setAlbumName:albumName trackCount:trackCount art:art fallbackColor:playlistRow.albumColor];

        [rowView addSubview:headerView];

        // Make headerView fill the entire row
        [NSLayoutConstraint activateConstraints:@[
            [headerView.leadingAnchor constraintEqualToAnchor:rowView.leadingAnchor],
            [headerView.trailingAnchor constraintEqualToAnchor:rowView.trailingAnchor],
            [headerView.topAnchor constraintEqualToAnchor:rowView.topAnchor],
            [headerView.bottomAnchor constraintEqualToAnchor:rowView.bottomAnchor]
        ]];

        return rowView;
    }
    return nil;  // Use default row view for regular tracks
}

- (NSView *)tableView:(NSTableView *)tableView viewForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row {
    if (row < 0 || row >= (NSInteger)_rows.size()) {
        return nil;
    }

    const PlaylistRow& playlistRow = _rows[row];
    NSString *identifier = tableColumn.identifier;

    // Group header rows are handled by rowViewForRow:, return nil for all columns
    if (playlistRow.isGroupHeader) {
        return nil;
    }

    // Regular track row
    const TrackData& track = _tracks[playlistRow.dataIndex];
    BOOL isPlaying = (track.playlistIndex == _playingIndex);

    // Playing indicator column
    if ([identifier isEqualToString:@"playing"]) {
        NSTableCellView *cell = [tableView makeViewWithIdentifier:@"PlayingCell" owner:self];
        if (!cell) {
            cell = [[NSTableCellView alloc] initWithFrame:NSZeroRect];
            cell.identifier = @"PlayingCell";

            NSTextField *textField = [[NSTextField alloc] initWithFrame:NSZeroRect];
            textField.bordered = NO;
            textField.editable = NO;
            textField.selectable = NO;
            textField.backgroundColor = [NSColor clearColor];
            textField.font = [NSFont systemFontOfSize:12];
            textField.alignment = NSTextAlignmentCenter;
            textField.translatesAutoresizingMaskIntoConstraints = NO;
            [cell addSubview:textField];
            cell.textField = textField;

            [NSLayoutConstraint activateConstraints:@[
                [textField.centerXAnchor constraintEqualToAnchor:cell.centerXAnchor],
                [textField.centerYAnchor constraintEqualToAnchor:cell.centerYAnchor]
            ]];
        }
        cell.textField.stringValue = isPlaying ? @"▶" : @"";
        cell.textField.textColor = [NSColor systemBlueColor];
        return cell;
    }

    // Text cells
    NSTableCellView *cell = [tableView makeViewWithIdentifier:identifier owner:self];
    if (!cell) {
        cell = [[NSTableCellView alloc] initWithFrame:NSZeroRect];
        cell.identifier = identifier;

        NSTextField *textField = [[NSTextField alloc] initWithFrame:NSZeroRect];
        textField.bordered = NO;
        textField.editable = NO;
        textField.selectable = NO;
        textField.backgroundColor = [NSColor clearColor];
        textField.font = [NSFont systemFontOfSize:13];
        textField.lineBreakMode = NSLineBreakByTruncatingTail;
        textField.translatesAutoresizingMaskIntoConstraints = NO;
        [cell addSubview:textField];
        cell.textField = textField;

        [NSLayoutConstraint activateConstraints:@[
            [textField.leadingAnchor constraintEqualToAnchor:cell.leadingAnchor constant:4],
            [textField.trailingAnchor constraintEqualToAnchor:cell.trailingAnchor constant:-4],
            [textField.centerYAnchor constraintEqualToAnchor:cell.centerYAnchor]
        ]];
    }

    // Highlight playing track
    cell.textField.textColor = isPlaying ? [NSColor systemBlueColor] : [NSColor labelColor];

    // Get value from columnValues map using column identifier
    std::string idStr = identifier.UTF8String;
    auto valueIt = track.columnValues.find(idStr);
    if (valueIt != track.columnValues.end()) {
        cell.textField.stringValue = [NSString stringWithUTF8String:valueIt->second.c_str()];
    } else {
        cell.textField.stringValue = @"";
    }

    // Apply alignment from column definition
    for (const auto& col : _columns) {
        if (col.identifier == idStr) {
            cell.textField.alignment = col.alignment;
            break;
        }
    }

    return cell;
}

- (void)tableView:(NSTableView *)tableView didAddRowView:(NSTableRowView *)rowView forRow:(NSInteger)row {
    if (row >= 0 && row < (NSInteger)_rows.size()) {
        const PlaylistRow& playlistRow = _rows[row];
        if (playlistRow.isGroupHeader) {
            rowView.backgroundColor = [[NSColor controlBackgroundColor] blendedColorWithFraction:0.05
                                                                                        ofColor:[NSColor labelColor]];
        }
    }
}

#pragma mark - Refresh from callbacks

- (void)refreshPlaylist {
    [self reloadPlaylistData];
}

- (void)updatePlayingIndex:(size_t)index {
    // Already on main thread from callback, but dispatch to be safe
    dispatch_async(dispatch_get_main_queue(), ^{
        self.playingIndex = index;
        [self.tableView reloadData];
    });
}

#pragma mark - Keyboard Actions

- (void)playSelectedTrack {
    NSInteger selectedRow = _tableView.selectedRow;
    if (selectedRow < 0 || selectedRow >= (NSInteger)_rows.size()) return;

    const PlaylistRow& playlistRow = _rows[selectedRow];
    if (playlistRow.isGroupHeader) return;

    const TrackData& track = _tracks[playlistRow.dataIndex];

    @try {
        try {
            auto pm = playlist_manager::get();
            if (!pm.is_valid()) return;

            t_size activePlaylist = pm->get_active_playlist();
            if (activePlaylist == pfc::infinite_size) return;

            pm->playlist_execute_default_action(activePlaylist, track.playlistIndex);
        } catch (...) {}
    } @catch (NSException *e) {}
}

- (void)deleteSelectedTracks {
    NSIndexSet *selectedRows = _tableView.selectedRowIndexes;
    if (selectedRows.count == 0) return;

    // Collect playlist indices of selected tracks (not group headers)
    std::vector<size_t> playlistIndicesToRemove;
    NSUInteger idx = [selectedRows firstIndex];
    while (idx != NSNotFound) {
        if (idx < _rows.size() && !_rows[idx].isGroupHeader) {
            playlistIndicesToRemove.push_back(_tracks[_rows[idx].dataIndex].playlistIndex);
        }
        idx = [selectedRows indexGreaterThanIndex:idx];
    }

    if (playlistIndicesToRemove.empty()) return;

    // Sort in descending order so we remove from end first (keeps indices valid)
    std::sort(playlistIndicesToRemove.begin(), playlistIndicesToRemove.end(), std::greater<size_t>());

    @try {
        try {
            auto pm = playlist_manager::get();
            if (!pm.is_valid()) return;

            t_size activePlaylist = pm->get_active_playlist();
            if (activePlaylist == pfc::infinite_size) return;

            // Create bit_array for items to remove
            pfc::bit_array_bittable mask(pm->playlist_get_item_count(activePlaylist));
            for (size_t idx : playlistIndicesToRemove) {
                mask.set(idx, true);
            }

            pm->playlist_remove_items(activePlaylist, mask);
            // Playlist callback will trigger reload
        } catch (...) {}
    } @catch (NSException *e) {}
}

#pragma mark - Drag and Drop (Source)

- (id<NSPasteboardWriting>)tableView:(NSTableView *)tableView pasteboardWriterForRow:(NSInteger)row {
    if (row < 0 || row >= (NSInteger)_rows.size()) return nil;

    const PlaylistRow& playlistRow = _rows[row];
    if (playlistRow.isGroupHeader) return nil;

    // Create a pasteboard item with the playlist index
    NSPasteboardItem *item = [[NSPasteboardItem alloc] init];
    NSString *indexString = [NSString stringWithFormat:@"%zu", _tracks[playlistRow.dataIndex].playlistIndex];
    [item setString:indexString forType:kPlaylistRowPasteboardType];
    return item;
}

- (void)tableView:(NSTableView *)tableView draggingSession:(NSDraggingSession *)session willBeginAtPoint:(NSPoint)screenPoint forRowIndexes:(NSIndexSet *)rowIndexes {
    // Optional: customize drag appearance
}

#pragma mark - Drag and Drop (Destination)

- (NSDragOperation)tableView:(NSTableView *)tableView validateDrop:(id<NSDraggingInfo>)info proposedRow:(NSInteger)row proposedDropOperation:(NSTableViewDropOperation)dropOperation {
    // Only allow drops between rows, not on rows
    if (dropOperation == NSTableViewDropOn) {
        [tableView setDropRow:row dropOperation:NSTableViewDropAbove];
    }

    NSPasteboard *pasteboard = info.draggingPasteboard;

    // Internal reordering
    if ([pasteboard.types containsObject:kPlaylistRowPasteboardType]) {
        return NSDragOperationMove;
    }

    // External files
    if ([pasteboard.types containsObject:NSPasteboardTypeFileURL]) {
        return NSDragOperationCopy;
    }

    return NSDragOperationNone;
}

- (BOOL)tableView:(NSTableView *)tableView acceptDrop:(id<NSDraggingInfo>)info row:(NSInteger)row dropOperation:(NSTableViewDropOperation)dropOperation {
    NSPasteboard *pasteboard = info.draggingPasteboard;

    // Convert row index to playlist index
    size_t targetPlaylistIndex = 0;
    if (row > 0 && row <= (NSInteger)_rows.size()) {
        // Find the playlist index to insert after
        for (NSInteger i = row - 1; i >= 0; i--) {
            if (!_rows[i].isGroupHeader) {
                targetPlaylistIndex = _tracks[_rows[i].dataIndex].playlistIndex + 1;
                break;
            }
        }
    }

    // Handle internal reordering
    if ([pasteboard.types containsObject:kPlaylistRowPasteboardType]) {
        NSArray<NSPasteboardItem *> *items = pasteboard.pasteboardItems;
        std::vector<size_t> sourceIndices;

        for (NSPasteboardItem *item in items) {
            NSString *indexString = [item stringForType:kPlaylistRowPasteboardType];
            if (indexString) {
                sourceIndices.push_back((size_t)[indexString integerValue]);
            }
        }

        if (sourceIndices.empty()) return NO;

        @try {
            try {
                auto pm = playlist_manager::get();
                if (!pm.is_valid()) return NO;

                t_size activePlaylist = pm->get_active_playlist();
                if (activePlaylist == pfc::infinite_size) return NO;

                t_size itemCount = pm->playlist_get_item_count(activePlaylist);

                // Create order array for reordering
                std::vector<t_size> order(itemCount);
                for (t_size i = 0; i < itemCount; i++) {
                    order[i] = i;
                }

                // Sort source indices
                std::sort(sourceIndices.begin(), sourceIndices.end());

                // Remove source items from order
                std::vector<t_size> movedItems;
                for (auto it = sourceIndices.rbegin(); it != sourceIndices.rend(); ++it) {
                    movedItems.insert(movedItems.begin(), order[*it]);
                    order.erase(order.begin() + *it);
                }

                // Adjust target index for removed items
                size_t adjustedTarget = targetPlaylistIndex;
                for (size_t srcIdx : sourceIndices) {
                    if (srcIdx < targetPlaylistIndex) {
                        adjustedTarget--;
                    }
                }
                if (adjustedTarget > order.size()) {
                    adjustedTarget = order.size();
                }

                // Insert moved items at target position
                order.insert(order.begin() + adjustedTarget, movedItems.begin(), movedItems.end());

                pm->playlist_reorder_items(activePlaylist, order.data(), itemCount);
                return YES;
            } catch (...) {
                return NO;
            }
        } @catch (NSException *e) {
            return NO;
        }
    }

    // Handle external file drops
    if ([pasteboard.types containsObject:NSPasteboardTypeFileURL]) {
        NSArray<NSURL *> *urls = [pasteboard readObjectsForClasses:@[[NSURL class]]
                                                           options:@{NSPasteboardURLReadingFileURLsOnlyKey: @YES}];
        if (urls.count == 0) return NO;

        @try {
            try {
                auto pm = playlist_manager::get();
                if (!pm.is_valid()) return NO;

                t_size activePlaylist = pm->get_active_playlist();
                if (activePlaylist == pfc::infinite_size) return NO;

                // Convert URLs to foobar2000 file paths
                pfc::string_list_impl paths;
                for (NSURL *url in urls) {
                    if (!url.isFileURL) continue;

                    // Use fileSystemRepresentation for proper encoding
                    pfc::string8 path;
                    path << "file://" << url.path.fileSystemRepresentation;
                    paths.add_item(path);
                }

                if (paths.get_count() == 0) return NO;

                // Capture target position
                size_t capturedTarget = targetPlaylistIndex;
                t_size capturedPlaylist = activePlaylist;

                // Use async version with callback
                auto filter = playlist_incoming_item_filter_v2::get();
                if (filter.is_valid()) {
                    auto notify = process_locations_notify::create([capturedPlaylist, capturedTarget](metadb_handle_list_cref items) {
                        if (items.get_count() == 0) return;

                        try {
                            auto pm = playlist_manager::get();
                            if (!pm.is_valid()) return;

                            // Verify playlist still exists
                            if (capturedPlaylist >= pm->get_playlist_count()) return;

                            pfc::bit_array_val selection(true);
                            pm->playlist_insert_items(capturedPlaylist, capturedTarget, items, selection);
                        } catch (...) {}
                    });

                    filter->process_locations_async(
                        paths,
                        playlist_incoming_item_filter_v2::op_flag_delay_ui,
                        nullptr,
                        nullptr,
                        nullptr,
                        notify
                    );
                }
                return YES;
            } catch (...) {
                return NO;
            }
        } @catch (NSException *e) {
            return NO;
        }
    }

    return NO;
}

#pragma mark - Context Menu Actions

- (void)contextMenuPlay:(id)sender {
    [self playSelectedTrack];
}

- (void)contextMenuRemove:(id)sender {
    [self deleteSelectedTracks];
}

- (void)contextMenuSelectAll:(id)sender {
    // Select all non-header rows
    NSMutableIndexSet *indices = [NSMutableIndexSet indexSet];
    for (size_t i = 0; i < _rows.size(); i++) {
        if (!_rows[i].isGroupHeader) {
            [indices addIndex:i];
        }
    }
    [_tableView selectRowIndexes:indices byExtendingSelection:NO];
}

- (BOOL)validateMenuItem:(NSMenuItem *)menuItem {
    SEL action = menuItem.action;

    if (action == @selector(contextMenuPlay:)) {
        // Enable only if a single track is selected
        NSInteger selectedRow = _tableView.selectedRow;
        if (selectedRow < 0 || selectedRow >= (NSInteger)_rows.size()) return NO;
        return !_rows[selectedRow].isGroupHeader;
    }

    if (action == @selector(contextMenuRemove:)) {
        // Enable if any tracks are selected
        NSIndexSet *selectedRows = _tableView.selectedRowIndexes;
        NSUInteger idx = [selectedRows firstIndex];
        while (idx != NSNotFound) {
            if (idx < _rows.size() && !_rows[idx].isGroupHeader) {
                return YES;
            }
            idx = [selectedRows indexGreaterThanIndex:idx];
        }
        return NO;
    }

    if (action == @selector(contextMenuSelectAll:)) {
        return _rows.size() > 0;
    }

    return YES;
}

@end

#pragma mark - Playlist and Playback Callbacks

namespace {

// Playlist callback to refresh on changes
class grouped_playlist_callback : public playlist_callback_impl_base {
public:
    grouped_playlist_callback() : playlist_callback_impl_base(
        playlist_callback::flag_on_items_added | playlist_callback::flag_on_items_removed |
        playlist_callback::flag_on_items_modified | playlist_callback::flag_on_items_reordered |
        playlist_callback::flag_on_playlist_activate | playlist_callback::flag_on_playlists_removed
    ) {}

    void on_items_added(t_size p_playlist, t_size p_start, metadb_handle_list_cref p_data, const bit_array& p_selection) override {
        (void)p_playlist; (void)p_start; (void)p_data; (void)p_selection;
        refresh();
    }
    void on_items_removed(t_size p_playlist, const bit_array& p_mask, t_size p_old_count, t_size p_new_count) override {
        (void)p_playlist; (void)p_mask; (void)p_old_count; (void)p_new_count;
        refresh();
    }
    void on_items_modified(t_size p_playlist, const bit_array& p_mask) override {
        (void)p_playlist; (void)p_mask;
        refresh();
    }
    void on_items_reordered(t_size p_playlist, const t_size* p_order, t_size p_count) override {
        (void)p_playlist; (void)p_order; (void)p_count;
        refresh();
    }
    void on_playlist_activate(t_size p_old, t_size p_new) override {
        (void)p_old; (void)p_new;
        refresh();
    }
    void on_playlists_removed(const bit_array& p_mask, t_size p_old_count, t_size p_new_count) override {
        (void)p_mask; (void)p_old_count; (void)p_new_count;
        refresh();
    }

private:
    void refresh() {
        dispatch_async(dispatch_get_main_queue(), ^{
            std::lock_guard<std::mutex> lock(g_panels_mutex);
            for (GroupedPlaylistPanel* panel : g_panels) {
                if (panel) {
                    [panel refreshPlaylist];
                }
            }
        });
    }
};

// Playback callback to update playing indicator
class grouped_playlist_playback_callback : public play_callback_impl_base {
public:
    grouped_playlist_playback_callback() : play_callback_impl_base(
        play_callback::flag_on_playback_new_track | play_callback::flag_on_playback_stop
    ) {}

    void on_playback_new_track(metadb_handle_ptr p_track) override {
        // Use playback_control to get the playing item location
        // This is more reliable than playlist_manager right after track change
        try {
            auto pc = playback_control::get();
            if (!pc.is_valid()) return;

            auto pm = playlist_manager::get();
            if (!pm.is_valid()) return;

            // Get the playing playlist and find the track index
            t_size playingPlaylist = pm->get_playing_playlist();
            if (playingPlaylist == pfc::infinite_size) return;

            // Find the track in the playlist by comparing handles
            t_size itemCount = pm->playlist_get_item_count(playingPlaylist);
            t_size foundIndex = pfc::infinite_size;

            for (t_size i = 0; i < itemCount; i++) {
                metadb_handle_ptr handle;
                if (pm->playlist_get_item_handle(handle, playingPlaylist, i)) {
                    if (handle == p_track) {
                        foundIndex = i;
                        break;
                    }
                }
            }

            dispatch_async(dispatch_get_main_queue(), ^{
                std::lock_guard<std::mutex> lock(g_panels_mutex);
                for (GroupedPlaylistPanel* panel : g_panels) {
                    if (panel) {
                        [panel updatePlayingIndex:foundIndex];
                    }
                }
            });
        } catch (...) {}
    }

    void on_playback_stop(play_control::t_stop_reason) override {
        dispatch_async(dispatch_get_main_queue(), ^{
            std::lock_guard<std::mutex> lock(g_panels_mutex);
            for (GroupedPlaylistPanel* panel : g_panels) {
                if (panel) {
                    [panel updatePlayingIndex:SIZE_MAX];
                }
            }
        });
    }
};

// Pointers for lazy initialization (created after services are ready)
static std::unique_ptr<grouped_playlist_callback> g_playlist_callback;
static std::unique_ptr<grouped_playlist_playback_callback> g_playback_callback;

// Initialize callbacks after foobar2000 services are ready
class grouped_playlist_initquit : public initquit {
public:
    void on_init() override {
        g_playlist_callback = std::make_unique<grouped_playlist_callback>();
        g_playback_callback = std::make_unique<grouped_playlist_playback_callback>();
    }
    void on_quit() override {
        g_playback_callback.reset();
        g_playlist_callback.reset();
    }
};

static initquit_factory_t<grouped_playlist_initquit> g_grouped_playlist_initquit;

#pragma mark - ui_element_mac registration

class ui_element_grouped_playlist : public ui_element_mac {
public:
    service_ptr instantiate(service_ptr arg) override {
        GroupedPlaylistPanel *panel = [[GroupedPlaylistPanel alloc] init];
        return fb2k::wrapNSObject(panel);
    }

    bool match_name(const char *name) override {
        return strcmp(name, "grouped_playlist") == 0 ||
               strcmp(name, "Grouped Playlist") == 0;
    }

    fb2k::stringRef get_name() override {
        return fb2k::makeString("Grouped Playlist");
    }

    GUID get_guid() override {
        return GUID{ 0xb2c3d4e5, 0xf6a7, 0x4890, { 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x90 } };
    }
};

FB2K_SERVICE_FACTORY(ui_element_grouped_playlist);

} // namespace
