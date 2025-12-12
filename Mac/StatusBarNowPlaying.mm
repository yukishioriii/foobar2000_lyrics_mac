//
//  StatusBarNowPlaying.mm
//  foo_sample
//
//  macOS menu bar status item showing current playing track
//  Click to show playlist menu
//

#import "stdafx.h"
#import "StatusBarNowPlaying.h"
#import <vector>
#import <mutex>
#import <functional>

// MARK: - Objective-C Implementation

// Cached playlist item
@interface CachedPlaylistItem : NSObject
@property (nonatomic, strong) NSString *title;
@property (nonatomic) NSInteger playlistIndex;
@property (nonatomic) NSInteger itemIndex;
@property (nonatomic) BOOL isPlaying;
@end

@implementation CachedPlaylistItem
@end

@interface StatusBarNowPlaying ()
@property (nonatomic, strong) NSStatusItem *statusItem;
@property (nonatomic, strong) NSString *currentArtist;
@property (nonatomic, strong) NSString *currentTitle;
@property (nonatomic) BOOL isPlaying;
@property (nonatomic) BOOL isPaused;
// Cached playlist data
@property (nonatomic, strong) NSString *cachedPlaylistName;
@property (nonatomic, strong) NSArray<CachedPlaylistItem *> *cachedPlaylistItems;
@property (nonatomic) NSInteger cachedPlayingIndex;
@property (nonatomic) NSInteger cachedTotalCount;
@end

@implementation StatusBarNowPlaying

+ (instancetype)shared {
    static StatusBarNowPlaying *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[StatusBarNowPlaying alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _isPlaying = NO;
        _isPaused = NO;
        [self setupStatusItem];
    }
    return self;
}

- (void)setupStatusItem {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];

        if (self.statusItem.button) {
            self.statusItem.button.title = @"♫ foobar2000";
            self.statusItem.button.target = self;
            self.statusItem.button.action = @selector(statusItemClicked:);
            [self.statusItem.button sendActionOn:NSEventMaskLeftMouseUp | NSEventMaskRightMouseUp];
        }
    });
}

- (void)updateTrack:(NSString *)artist title:(NSString *)title {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.currentArtist = artist;
        self.currentTitle = title;
        [self updateDisplay];
    });
}

- (void)updatePlaybackState:(BOOL)isPlaying isPaused:(BOOL)isPaused {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.isPlaying = isPlaying;
        self.isPaused = isPaused;
        [self updateDisplay];
    });
}

- (void)clearTrack {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.currentArtist = nil;
        self.currentTitle = nil;
        self.isPlaying = NO;
        self.isPaused = NO;
        [self updateDisplay];
    });
}

- (void)updateDisplay {
    if (!self.statusItem.button) return;

    NSString *displayText;

    if (self.isPlaying && self.currentTitle.length > 0) {
        NSString *icon = self.isPaused ? @"❚❚" : @"▶";
        NSString *trackInfo = self.currentTitle;

        // Truncate if too long
        if (trackInfo.length > 40) {
            trackInfo = [[trackInfo substringToIndex:37] stringByAppendingString:@"..."];
        }

        displayText = [NSString stringWithFormat:@"%@ %@", icon, trackInfo];
    } else {
        displayText = @"♫ foobar2000";
    }

    self.statusItem.button.title = displayText;
}

- (void)statusItemClicked:(id)sender {
    [self showMenu];
}

- (void)showMenu {
    NSLog(@"StatusBarNowPlaying: showMenu called");

    NSMenu *menu = [[NSMenu alloc] init];

    // Now playing header
    if (self.isPlaying && self.currentTitle.length > 0) {
        NSString *nowPlaying;
        if (self.currentArtist.length > 0) {
            nowPlaying = [NSString stringWithFormat:@"%@ - %@", self.currentArtist, self.currentTitle];
        } else {
            nowPlaying = self.currentTitle;
        }
        NSMenuItem *nowPlayingItem = [[NSMenuItem alloc] initWithTitle:nowPlaying action:nil keyEquivalent:@""];
        nowPlayingItem.enabled = NO;
        [menu addItem:nowPlayingItem];
        [menu addItem:[NSMenuItem separatorItem]];
    }

    // Playback controls
    NSString *playPauseTitle = (self.isPlaying && !self.isPaused) ? @"Pause" : @"Play";
    NSMenuItem *playPauseItem = [[NSMenuItem alloc] initWithTitle:playPauseTitle
                                                           action:@selector(playPause:)
                                                    keyEquivalent:@""];
    playPauseItem.target = self;
    [menu addItem:playPauseItem];

    NSMenuItem *prevItem = [[NSMenuItem alloc] initWithTitle:@"Previous"
                                                      action:@selector(previousTrack:)
                                               keyEquivalent:@""];
    prevItem.target = self;
    [menu addItem:prevItem];

    NSMenuItem *nextItem = [[NSMenuItem alloc] initWithTitle:@"Next"
                                                      action:@selector(nextTrack:)
                                               keyEquivalent:@""];
    nextItem.target = self;
    [menu addItem:nextItem];

    [menu addItem:[NSMenuItem separatorItem]];

    // Show foobar2000 window
    NSMenuItem *showItem = [[NSMenuItem alloc] initWithTitle:@"Show foobar2000"
                                                      action:@selector(showMainWindow:)
                                               keyEquivalent:@""];
    showItem.target = self;
    [menu addItem:showItem];

    NSLog(@"StatusBarNowPlaying: showing menu");
    self.statusItem.menu = menu;
    [self.statusItem.button performClick:nil];
    self.statusItem.menu = nil;
    NSLog(@"StatusBarNowPlaying: menu done");
}

- (NSMenu *)buildPlaylistMenu {
    @try {
        // Wrap foobar2000 API calls in try-catch
        try {
            auto pm = playlist_manager::get();
            if (!pm.is_valid()) return nil;

            t_size playingPlaylist = pm->get_playing_playlist();
            if (playingPlaylist == pfc::infinite_size) {
                playingPlaylist = pm->get_active_playlist();
            }

            if (playingPlaylist == pfc::infinite_size || pm->get_playlist_count() == 0) {
                return nil;
            }

            NSMenu *submenu = [[NSMenu alloc] init];

            // Get playing item
            t_size playingItem = pfc::infinite_size;
            pm->get_playing_item_location(nullptr, &playingItem);

            // Get playlist name
            pfc::string8 playlistName;
            pm->playlist_get_name(playingPlaylist, playlistName);

            NSMenuItem *headerItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithUTF8String:playlistName.c_str()]
                                                                action:nil
                                                         keyEquivalent:@""];
            headerItem.enabled = NO;
            [submenu addItem:headerItem];
            [submenu addItem:[NSMenuItem separatorItem]];

            // Get items
            t_size itemCount = pm->playlist_get_item_count(playingPlaylist);
            if (itemCount == 0) {
                NSMenuItem *emptyItem = [[NSMenuItem alloc] initWithTitle:@"(Empty playlist)" action:nil keyEquivalent:@""];
                emptyItem.enabled = NO;
                [submenu addItem:emptyItem];
                return submenu;
            }

            t_size maxItems = MIN(itemCount, (t_size)50);

            // Calculate range around playing item
            t_size startItem = 0;
            if (playingItem != pfc::infinite_size && itemCount > maxItems) {
                if (playingItem > maxItems / 2) {
                    startItem = playingItem - maxItems / 2;
                }
                if (startItem + maxItems > itemCount) {
                    startItem = itemCount - maxItems;
                }
            }

            // Format items
            titleformat_object::ptr script;
            auto tfc = titleformat_compiler::get();
            if (tfc.is_valid()) {
                tfc->compile_safe_ex(script, "[%tracknumber%. ]%title%");
            }

            for (t_size i = startItem; i < startItem + maxItems && i < itemCount; i++) {
                pfc::string8 itemText;
                if (script.is_valid()) {
                    pm->playlist_item_format_title(playingPlaylist, i, nullptr, itemText, script, nullptr,
                                                   playback_control::display_level_none);
                } else {
                    itemText = "Track";
                }

                // Truncate if needed
                if (itemText.get_length() > 50) {
                    itemText.truncate(47);
                    itemText << "...";
                }

                NSString *title = [NSString stringWithUTF8String:itemText.c_str()];
                if (!title) title = @"(Unknown)";

                NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title
                                                              action:@selector(playPlaylistItem:)
                                                       keyEquivalent:@""];
                item.target = self;
                // Encode both playlist and item index in tag: high 16 bits = playlist, low 48 bits = item
                item.tag = (NSInteger)((playingPlaylist << 48) | (i & 0xFFFFFFFFFFFF));

                if (i == playingItem) {
                    item.state = NSControlStateValueOn;
                }

                [submenu addItem:item];
            }

            if (itemCount > maxItems) {
                [submenu addItem:[NSMenuItem separatorItem]];
                NSString *moreText = [NSString stringWithFormat:@"(%lu items total)", (unsigned long)itemCount];
                NSMenuItem *moreItem = [[NSMenuItem alloc] initWithTitle:moreText action:nil keyEquivalent:@""];
                moreItem.enabled = NO;
                [submenu addItem:moreItem];
            }

            return submenu;
        } catch (const std::exception& e) {
            NSLog(@"StatusBarNowPlaying: Exception building playlist menu: %s", e.what());
            return nil;
        } catch (...) {
            NSLog(@"StatusBarNowPlaying: Unknown exception building playlist menu");
            return nil;
        }
    } @catch (NSException *exception) {
        NSLog(@"StatusBarNowPlaying: NSException building playlist menu: %@", exception);
        return nil;
    }
}

// MARK: - Menu Actions

- (void)playPause:(id)sender {
    @try {
        try {
            auto pc = playback_control::get();
            if (pc.is_valid()) {
                if (pc->is_playing()) {
                    pc->toggle_pause();
                } else {
                    pc->play_or_unpause();
                }
            }
        } catch (...) {
            NSLog(@"StatusBarNowPlaying: Exception in playPause");
        }
    } @catch (NSException *e) {
        NSLog(@"StatusBarNowPlaying: NSException in playPause: %@", e);
    }
}

- (void)stop:(id)sender {
    @try {
        try {
            auto pc = playback_control::get();
            if (pc.is_valid()) {
                pc->stop();
            }
        } catch (...) {
            NSLog(@"StatusBarNowPlaying: Exception in stop");
        }
    } @catch (NSException *e) {
        NSLog(@"StatusBarNowPlaying: NSException in stop: %@", e);
    }
}

- (void)previousTrack:(id)sender {
    @try {
        try {
            auto pc = playback_control::get();
            if (pc.is_valid()) {
                pc->previous();
            }
        } catch (...) {
            NSLog(@"StatusBarNowPlaying: Exception in previousTrack");
        }
    } @catch (NSException *e) {
        NSLog(@"StatusBarNowPlaying: NSException in previousTrack: %@", e);
    }
}

- (void)nextTrack:(id)sender {
    @try {
        try {
            auto pc = playback_control::get();
            if (pc.is_valid()) {
                pc->next();
            }
        } catch (...) {
            NSLog(@"StatusBarNowPlaying: Exception in nextTrack");
        }
    } @catch (NSException *e) {
        NSLog(@"StatusBarNowPlaying: NSException in nextTrack: %@", e);
    }
}

- (void)playPlaylistItem:(NSMenuItem *)sender {
    @try {
        try {
            // Decode playlist and item index from tag
            NSInteger tag = sender.tag;
            t_size playlistIndex = (t_size)((tag >> 48) & 0xFFFF);
            t_size itemIndex = (t_size)(tag & 0xFFFFFFFFFFFF);

            NSLog(@"StatusBarNowPlaying: Playing playlist %zu item %zu", playlistIndex, itemIndex);

            auto pm = playlist_manager::get();
            if (pm.is_valid()) {
                // Validate indices before executing
                if (playlistIndex < pm->get_playlist_count()) {
                    t_size itemCount = pm->playlist_get_item_count(playlistIndex);
                    if (itemIndex < itemCount) {
                        pm->playlist_execute_default_action(playlistIndex, itemIndex);
                    } else {
                        NSLog(@"StatusBarNowPlaying: Invalid item index %zu (count: %zu)", itemIndex, itemCount);
                    }
                } else {
                    NSLog(@"StatusBarNowPlaying: Invalid playlist index %zu", playlistIndex);
                }
            }
        } catch (const std::exception& e) {
            NSLog(@"StatusBarNowPlaying: Exception in playPlaylistItem: %s", e.what());
        } catch (...) {
            NSLog(@"StatusBarNowPlaying: Unknown exception in playPlaylistItem");
        }
    } @catch (NSException *e) {
        NSLog(@"StatusBarNowPlaying: NSException in playPlaylistItem: %@", e);
    }
}

- (void)showMainWindow:(id)sender {
    // Bring foobar2000 to front
    [NSApp activateIgnoringOtherApps:YES];
    for (NSWindow *window in [NSApp windows]) {
        if ([window isKindOfClass:[NSWindow class]] && window.canBecomeMainWindow) {
            [window makeKeyAndOrderFront:nil];
            break;
        }
    }
}

- (void)destroy {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.statusItem) {
            [[NSStatusBar systemStatusBar] removeStatusItem:self.statusItem];
            self.statusItem = nil;
        }
    });
}

// MARK: - Playlist Cache

- (void)refreshPlaylistCache {
    // This method is called from playback callbacks where foobar2000 API calls are safe
    // It caches the playlist data so we don't need to call APIs when building the menu

    @try {
        try {
            auto pm = playlist_manager::get();
            if (!pm.is_valid()) {
                [self clearPlaylistCache];
                return;
            }

            t_size playingPlaylist = pm->get_playing_playlist();
            if (playingPlaylist == pfc::infinite_size) {
                playingPlaylist = pm->get_active_playlist();
            }

            if (playingPlaylist == pfc::infinite_size || pm->get_playlist_count() == 0) {
                [self clearPlaylistCache];
                return;
            }

            // Get playing item
            t_size playingItem = pfc::infinite_size;
            pm->get_playing_item_location(nullptr, &playingItem);

            // Get playlist name
            pfc::string8 playlistName;
            pm->playlist_get_name(playingPlaylist, playlistName);
            NSString *nsPlaylistName = [NSString stringWithUTF8String:playlistName.c_str()];

            // Get items
            t_size itemCount = pm->playlist_get_item_count(playingPlaylist);
            if (itemCount == 0) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.cachedPlaylistName = nsPlaylistName;
                    self.cachedPlaylistItems = @[];
                    self.cachedPlayingIndex = -1;
                    self.cachedTotalCount = 0;
                });
                return;
            }

            t_size maxItems = MIN(itemCount, (t_size)50);

            // Calculate range around playing item
            t_size startItem = 0;
            if (playingItem != pfc::infinite_size && itemCount > maxItems) {
                if (playingItem > maxItems / 2) {
                    startItem = playingItem - maxItems / 2;
                }
                if (startItem + maxItems > itemCount) {
                    startItem = itemCount - maxItems;
                }
            }

            // Format items
            titleformat_object::ptr script;
            auto tfc = titleformat_compiler::get();
            if (tfc.is_valid()) {
                tfc->compile_safe_ex(script, "[%tracknumber%. ]%title%");
            }

            NSMutableArray<CachedPlaylistItem *> *items = [NSMutableArray array];
            NSInteger cachedPlayingIdx = -1;

            for (t_size i = startItem; i < startItem + maxItems && i < itemCount; i++) {
                pfc::string8 itemText;
                if (script.is_valid()) {
                    pm->playlist_item_format_title(playingPlaylist, i, nullptr, itemText, script, nullptr,
                                                   playback_control::display_level_none);
                } else {
                    itemText = "Track";
                }

                // Truncate if needed
                if (itemText.get_length() > 50) {
                    itemText.truncate(47);
                    itemText << "...";
                }

                NSString *title = [NSString stringWithUTF8String:itemText.c_str()];
                if (!title) title = @"(Unknown)";

                CachedPlaylistItem *cachedItem = [[CachedPlaylistItem alloc] init];
                cachedItem.title = title;
                cachedItem.playlistIndex = (NSInteger)playingPlaylist;
                cachedItem.itemIndex = (NSInteger)i;
                cachedItem.isPlaying = (i == playingItem);

                if (i == playingItem) {
                    cachedPlayingIdx = (NSInteger)items.count;
                }

                [items addObject:cachedItem];
            }

            // Store in properties on main thread
            NSArray<CachedPlaylistItem *> *finalItems = [items copy];
            NSInteger totalCount = (NSInteger)itemCount;

            dispatch_async(dispatch_get_main_queue(), ^{
                self.cachedPlaylistName = nsPlaylistName;
                self.cachedPlaylistItems = finalItems;
                self.cachedPlayingIndex = cachedPlayingIdx;
                self.cachedTotalCount = totalCount;
            });

        } catch (const std::exception& e) {
            NSLog(@"StatusBarNowPlaying: Exception refreshing playlist cache: %s", e.what());
            [self clearPlaylistCache];
        } catch (...) {
            NSLog(@"StatusBarNowPlaying: Unknown exception refreshing playlist cache");
            [self clearPlaylistCache];
        }
    } @catch (NSException *exception) {
        NSLog(@"StatusBarNowPlaying: NSException refreshing playlist cache: %@", exception);
        [self clearPlaylistCache];
    }
}

- (void)clearPlaylistCache {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.cachedPlaylistName = nil;
        self.cachedPlaylistItems = nil;
        self.cachedPlayingIndex = -1;
        self.cachedTotalCount = 0;
    });
}

- (void)addPlaylistItemsToMenu:(NSMenu *)menu {
    // Add playlist items directly to menu using cached data - no foobar2000 API calls
    if (!self.cachedPlaylistName || self.cachedPlaylistItems.count == 0) {
        return;
    }

    // Header with playlist name
    NSMenuItem *headerItem = [[NSMenuItem alloc] initWithTitle:self.cachedPlaylistName
                                                        action:nil
                                                 keyEquivalent:@""];
    headerItem.enabled = NO;
    [menu addItem:headerItem];
    [menu addItem:[NSMenuItem separatorItem]];

    // Add cached items
    for (CachedPlaylistItem *cachedItem in self.cachedPlaylistItems) {
        NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:cachedItem.title
                                                      action:@selector(playPlaylistItem:)
                                               keyEquivalent:@""];
        item.target = self;
        // Encode both playlist and item index in tag
        item.tag = (cachedItem.playlistIndex << 48) | (cachedItem.itemIndex & 0xFFFFFFFFFFFF);

        if (cachedItem.isPlaying) {
            item.state = NSControlStateValueOn;
        }

        [menu addItem:item];
    }

    // Show total count if there are more items
    if (self.cachedTotalCount > (NSInteger)self.cachedPlaylistItems.count) {
        [menu addItem:[NSMenuItem separatorItem]];
        NSString *moreText = [NSString stringWithFormat:@"(%ld items total)", (long)self.cachedTotalCount];
        NSMenuItem *moreItem = [[NSMenuItem alloc] initWithTitle:moreText action:nil keyEquivalent:@""];
        moreItem.enabled = NO;
        [menu addItem:moreItem];
    }

    [menu addItem:[NSMenuItem separatorItem]];
}

@end

// MARK: - C++ Interface Implementation

namespace statusbar_nowplaying {

void update_track(const char* artist, const char* title) {
    NSString *nsArtist = artist ? [NSString stringWithUTF8String:artist] : nil;
    NSString *nsTitle = title ? [NSString stringWithUTF8String:title] : nil;
    [[StatusBarNowPlaying shared] updateTrack:nsArtist title:nsTitle];
}

void update_playback_state(bool is_playing, bool is_paused) {
    [[StatusBarNowPlaying shared] updatePlaybackState:is_playing isPaused:is_paused];
}

void clear() {
    [[StatusBarNowPlaying shared] clearTrack];
}

void initialize() {
    // Force creation of singleton on main thread
    dispatch_async(dispatch_get_main_queue(), ^{
        [StatusBarNowPlaying shared];
    });
}

void refresh_playlist_cache() {
    // Use fb2k::inMainThread to ensure we're on foobar's main thread for API calls
    fb2k::inMainThread([]() {
        try {
            auto pm = playlist_manager::get();
            if (!pm.is_valid()) return;

            t_size playingPlaylist = pm->get_playing_playlist();
            if (playingPlaylist == pfc::infinite_size) {
                playingPlaylist = pm->get_active_playlist();
            }

            if (playingPlaylist == pfc::infinite_size || pm->get_playlist_count() == 0) {
                return;
            }

            // Get playing item
            t_size playingItem = pfc::infinite_size;
            pm->get_playing_item_location(nullptr, &playingItem);

            // Get playlist name
            pfc::string8 playlistName;
            pm->playlist_get_name(playingPlaylist, playlistName);
            NSString *nsPlaylistName = [NSString stringWithUTF8String:playlistName.c_str()];

            // Get items
            t_size itemCount = pm->playlist_get_item_count(playingPlaylist);
            if (itemCount == 0) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    StatusBarNowPlaying *sb = [StatusBarNowPlaying shared];
                    sb.cachedPlaylistName = nsPlaylistName;
                    sb.cachedPlaylistItems = @[];
                    sb.cachedPlayingIndex = -1;
                    sb.cachedTotalCount = 0;
                });
                return;
            }

            t_size maxItems = MIN(itemCount, (t_size)50);

            // Calculate range around playing item
            t_size startItem = 0;
            if (playingItem != pfc::infinite_size && itemCount > maxItems) {
                if (playingItem > maxItems / 2) {
                    startItem = playingItem - maxItems / 2;
                }
                if (startItem + maxItems > itemCount) {
                    startItem = itemCount - maxItems;
                }
            }

            // Format items
            titleformat_object::ptr script;
            auto tfc = titleformat_compiler::get();
            if (tfc.is_valid()) {
                tfc->compile_safe_ex(script, "[%tracknumber%. ]%title%");
            }

            NSMutableArray<CachedPlaylistItem *> *items = [NSMutableArray array];
            NSInteger cachedPlayingIdx = -1;

            for (t_size i = startItem; i < startItem + maxItems && i < itemCount; i++) {
                pfc::string8 itemText;
                if (script.is_valid()) {
                    pm->playlist_item_format_title(playingPlaylist, i, nullptr, itemText, script, nullptr,
                                                   playback_control::display_level_none);
                } else {
                    itemText = "Track";
                }

                // Truncate if needed
                if (itemText.get_length() > 50) {
                    itemText.truncate(47);
                    itemText << "...";
                }

                NSString *title = [NSString stringWithUTF8String:itemText.c_str()];
                if (!title) title = @"(Unknown)";

                CachedPlaylistItem *cachedItem = [[CachedPlaylistItem alloc] init];
                cachedItem.title = title;
                cachedItem.playlistIndex = (NSInteger)playingPlaylist;
                cachedItem.itemIndex = (NSInteger)i;
                cachedItem.isPlaying = (i == playingItem);

                if (i == playingItem) {
                    cachedPlayingIdx = (NSInteger)[items count];
                }

                [items addObject:cachedItem];
            }

            // Store in properties on macOS main thread
            NSArray<CachedPlaylistItem *> *finalItems = [items copy];
            NSInteger totalCount = (NSInteger)itemCount;

            dispatch_async(dispatch_get_main_queue(), ^{
                StatusBarNowPlaying *sb = [StatusBarNowPlaying shared];
                sb.cachedPlaylistName = nsPlaylistName;
                sb.cachedPlaylistItems = finalItems;
                sb.cachedPlayingIndex = cachedPlayingIdx;
                sb.cachedTotalCount = totalCount;
            });

        } catch (...) {
            // Silently ignore errors
        }
    });
}

void shutdown() {
    [[StatusBarNowPlaying shared] destroy];
}

} // namespace statusbar_nowplaying

// MARK: - Playback Callbacks

namespace {

class statusbar_play_callback : public play_callback_static {
public:
    unsigned get_flags() override {
        return flag_on_playback_new_track | flag_on_playback_stop |
               flag_on_playback_pause | flag_on_playback_starting;
    }

    void on_playback_starting(play_control::t_track_command cmd, bool paused) override {
        try {
            statusbar_nowplaying::update_playback_state(true, paused);
        } catch (...) {}
    }

    void on_playback_new_track(metadb_handle_ptr track) override {
        try {
            if (track.is_valid()) {
                // Get track info
                pfc::string8 artist, title;

                titleformat_object::ptr script_artist, script_title;
                auto tfc = titleformat_compiler::get();
                if (tfc.is_valid()) {
                    tfc->compile_safe_ex(script_artist, "%artist%");
                    tfc->compile_safe_ex(script_title, "%title%");

                    if (script_artist.is_valid()) {
                        track->format_title(nullptr, artist, script_artist, nullptr);
                    }
                    if (script_title.is_valid()) {
                        track->format_title(nullptr, title, script_title, nullptr);
                    }
                }

                statusbar_nowplaying::update_track(artist.c_str(), title.c_str());
                statusbar_nowplaying::update_playback_state(true, false);
            }
        } catch (...) {}
    }

    void on_playback_stop(play_control::t_stop_reason reason) override {
        try {
            statusbar_nowplaying::update_playback_state(false, false);
            if (reason != play_control::stop_reason_starting_another) {
                statusbar_nowplaying::clear();
            }
        } catch (...) {}
    }

    void on_playback_seek(double time) override {}

    void on_playback_pause(bool state) override {
        try {
            auto pc = playback_control::get();
            bool playing = pc.is_valid() ? pc->is_playing() : false;
            statusbar_nowplaying::update_playback_state(playing, state);
        } catch (...) {}
    }

    void on_playback_edited(metadb_handle_ptr track) override {}
    void on_playback_dynamic_info(const file_info& info) override {}
    void on_playback_dynamic_info_track(const file_info& info) override {}
    void on_playback_time(double time) override {}
    void on_volume_change(float new_val) override {}
};

play_callback_static_factory_t<statusbar_play_callback> g_statusbar_play_callback;

// Initialize/shutdown on component load/unload
class statusbar_initquit : public initquit {
public:
    void on_init() override {
        statusbar_nowplaying::initialize();
    }

    void on_quit() override {
        statusbar_nowplaying::shutdown();
    }
};

initquit_factory_t<statusbar_initquit> g_statusbar_initquit;

} // namespace
