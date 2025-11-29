#include "stdafx.h"
#include "../SDK/console_manager.h"
#include <curl/curl.h>
#include <pugixml.hpp>
#include "cJSON.h"

#include <tidy.h>
#include <tidybuffio.h>
#include <stdio.h>

#include <fstream>
#include <regex>

#include <string>
#include <iterator>

#include <iostream>
#include <regex>
#include <vector>
#include <functional>
#include <cctype>
#include <algorithm>
#include <utility>
#include <unordered_map>

// HTML entity decoder for cleaning lyrics
static std::string decode_html_entities(const std::string& input) {
    static const std::unordered_map<std::string, std::string> entities = {
        {"&amp;", "&"},
        {"&lt;", "<"},
        {"&gt;", ">"},
        {"&quot;", "\""},
        {"&apos;", "'"},
        {"&#39;", "'"},
        {"&nbsp;", " "},
        {"&ndash;", "\xe2\x80\x93"},  // en-dash
        {"&mdash;", "\xe2\x80\x94"},  // em-dash
        {"&lsquo;", "\xe2\x80\x98"},  // left single quote
        {"&rsquo;", "\xe2\x80\x99"},  // right single quote (apostrophe)
        {"&ldquo;", "\xe2\x80\x9c"},  // left double quote
        {"&rdquo;", "\xe2\x80\x9d"},  // right double quote
        {"&hellip;", "\xe2\x80\xa6"}, // ellipsis
        {"&copy;", "\xc2\xa9"},       // copyright
        {"&reg;", "\xc2\xae"},        // registered
        {"&trade;", "\xe2\x84\xa2"},  // trademark
        {"&times;", "\xc3\x97"},      // multiplication
        {"&divide;", "\xc3\xb7"},     // division
        {"&deg;", "\xc2\xb0"},        // degree
        {"&plusmn;", "\xc2\xb1"},     // plus-minus
        {"&frac12;", "\xc2\xbd"},     // 1/2
        {"&frac14;", "\xc2\xbc"},     // 1/4
        {"&frac34;", "\xc2\xbe"},     // 3/4
        {"&cent;", "\xc2\xa2"},       // cent
        {"&pound;", "\xc2\xa3"},      // pound
        {"&euro;", "\xe2\x82\xac"},   // euro
        {"&yen;", "\xc2\xa5"},        // yen
    };

    std::string result = input;

    // Replace named entities
    for (const auto& pair : entities) {
        size_t pos = 0;
        while ((pos = result.find(pair.first, pos)) != std::string::npos) {
            result.replace(pos, pair.first.length(), pair.second);
            pos += pair.second.length();
        }
    }

    // Replace numeric entities (&#NNN;)
    std::regex numeric_entity("&#([0-9]+);");
    std::smatch match;
    std::string temp = result;
    result.clear();

    size_t last_pos = 0;
    std::string::const_iterator searchStart(temp.cbegin());
    while (std::regex_search(searchStart, temp.cend(), match, numeric_entity)) {
        size_t match_pos = match.position() + (searchStart - temp.cbegin());
        result += temp.substr(last_pos, match_pos - last_pos);

        int code = std::stoi(match[1].str());
        if (code < 128) {
            result += static_cast<char>(code);
        } else if (code < 0x800) {
            result += static_cast<char>(0xC0 | (code >> 6));
            result += static_cast<char>(0x80 | (code & 0x3F));
        } else {
            result += static_cast<char>(0xE0 | (code >> 12));
            result += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
            result += static_cast<char>(0x80 | (code & 0x3F));
        }

        last_pos = match_pos + match[0].length();
        searchStart = match.suffix().first;
    }
    result += temp.substr(last_pos);

    // Replace hex entities (&#xHHHH;)
    std::regex hex_entity("&#[xX]([0-9a-fA-F]+);");
    temp = result;
    result.clear();

    last_pos = 0;
    searchStart = temp.cbegin();
    while (std::regex_search(searchStart, temp.cend(), match, hex_entity)) {
        size_t match_pos = match.position() + (searchStart - temp.cbegin());
        result += temp.substr(last_pos, match_pos - last_pos);

        int code = std::stoi(match[1].str(), nullptr, 16);
        if (code < 128) {
            result += static_cast<char>(code);
        } else if (code < 0x800) {
            result += static_cast<char>(0xC0 | (code >> 6));
            result += static_cast<char>(0x80 | (code & 0x3F));
        } else {
            result += static_cast<char>(0xE0 | (code >> 12));
            result += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
            result += static_cast<char>(0x80 | (code & 0x3F));
        }

        last_pos = match_pos + match[0].length();
        searchStart = match.suffix().first;
    }
    result += temp.substr(last_pos);

    return result;
}

// Identifier of our context menu group. Substitute with your own when reusing code.
static const GUID guid_mygroup = { 0x572de7f4, 0xcbdf, 0x479a, { 0x97, 0x26, 0xa, 0xb0, 0x97, 0x47, 0x69, 0xe3 } };


// Switch to contextmenu_group_factory to embed your commands in the root menu but separated from other commands.

//static contextmenu_group_factory g_mygroup(guid_mygroup, contextmenu_groups::root, 0);
static contextmenu_group_popup_factory g_mygroup(guid_mygroup, contextmenu_groups::root, "Lyrics find", 0);

static void RunWack(metadb_handle_list_cref data);

static void RunQQMusic(metadb_handle_list_cref data);

static void RunNetEase(metadb_handle_list_cref data);

static void RunMusixmatch(metadb_handle_list_cref data);

static void RunSongLyrics(metadb_handle_list_cref data);

static void RunAutoSearch(metadb_handle_list_cref data);

static void RunFromFile(metadb_handle_list_cref data);

static void RunAutoSearchSaveFile(metadb_handle_list_cref data, bool show_popup = true);

static void RunAutoSearchSaveTag(metadb_handle_list_cref data);

metadb_v2_rec_t get_full_metadata(metadb_handle_ptr track);

static std::pair<std::string, std::string> auto_search_get_best_lyrics(
    const metadb_v2_rec_t& track_info,
    metadb_handle_ptr track,
    pfc::string_formatter& message);

void RunCalculatePeak(metadb_handle_list_cref data); //decode.cpp

void RunCopyFiles(metadb_handle_list_cref data); // IO.cpp
void RunAlterTagsLL(metadb_handle_list_cref data); // IO.cpp

void RunUIAndThreads( metadb_handle_list_cref data ); // ui_and_threads.cpp

namespace { // anon namespace local classes for good measure
class myFilter : public file_info_filter {
    public:
    bool apply_filter(metadb_handle_ptr p_location, t_filestats p_stats, file_info & p_info) {
        p_info.meta_set("comment", "rule of nature was here");
        // return true to write changes tags to the file, false to suppress the update
        return true;
    }
};
}

static void RunAlterTags(metadb_handle_list_cref data) {
    // Simple alter-file-tags functionality
    
    const auto wndParent = core_api::get_main_window();
    
    // Filter object that applies our edits to the file tags
    auto filter = fb2k::service_new<myFilter>();
    
    auto notify = fb2k::makeCompletionNotify( [] (unsigned code) {
        // Code values are metadb_io::t_update_info_state enum
        FB2K_console_formatter() << "Tag update finished, code: " << code;
    } );
    
    // Flags
    // Indicate that we're aware of fb2k 1.3+ partial info semantics
    const uint32_t flags = metadb_io_v2::op_flag_partial_info_aware;
    
    metadb_io_v2::get()->update_info_async(data, filter, wndParent, flags, notify);
}

// Simple context menu item class.
class myitem : public contextmenu_item_simple {
    typedef contextmenu_item_simple super_t;
    public:
    enum {
//        wack = 0,
        autosearch_save_file_silent,
        autosearch_save_file,
//        autosearch = 0,
        qqmusic,
        netease,
        musixmatch,
        songlyrics,
//        fromfile,
//        autosearch_save_tag,
        cmd_total
    };
    GUID get_parent() {return guid_mygroup;}
    unsigned get_num_items() {return cmd_total;}
    void get_item_name(unsigned p_index,pfc::string_base & p_out) {
        switch(p_index) {
//            case wack: p_out = "AZLyrics"; break;
            case qqmusic: p_out = "QQ Music"; break;
            case netease: p_out = "NetEase"; break;
            case musixmatch: p_out = "Musixmatch"; break;
            case songlyrics: p_out = "SongLyrics"; break;
//            case autosearch: p_out = "Auto Search (Best Match)"; break;
//            case fromfile: p_out = "From File Metadata"; break;
            case autosearch_save_file: p_out = "Search & Save"; break;
            case autosearch_save_file_silent: p_out = "Search & Save (Silent)"; break;
//            case autosearch_save_tag: p_out = "Auto Search & Save to Tag"; break;
            default: uBugCheck(); // should never happen unless somebody called us with invalid parameters - bail
        }
    }
    void context_command(unsigned p_index,metadb_handle_list_cref p_data,const GUID& p_caller) {
        switch(p_index) {
//            case wack:
//                RunWack(p_data);
//                break;
            case qqmusic:
                RunQQMusic(p_data);
                break;
            case netease:
                RunNetEase(p_data);
                break;
            case musixmatch:
                RunMusixmatch(p_data);
                break;
            case songlyrics:
                RunSongLyrics(p_data);
                break;
//            case autosearch:
//                RunAutoSearch(p_data);
//                break;
//            case fromfile:
//                RunFromFile(p_data);
//                break;
            case autosearch_save_file:
                RunAutoSearchSaveFile(p_data, true);
                break;
            case autosearch_save_file_silent:
                RunAutoSearchSaveFile(p_data, false);
                break;
//            case autosearch_save_tag:
//                RunAutoSearchSaveTag(p_data);
//                break;
            default:
                uBugCheck();
        }
    }
    GUID get_item_guid(unsigned p_index) {
        // These GUIDs identify our context menu items. Substitute with your own GUIDs when reusing code.
//        static const GUID guid_wack = { 0x4021c79d, 0x9340, 0x423b, { 0xa3, 0xe2, 0x8e, 0x1e, 0xda, 0x87, 0x13, 0x7f } };
        static const GUID guid_qqmusic = { 0x5b32d81e, 0xa451, 0x4c9a, { 0xb4, 0xf3, 0x9f, 0x2f, 0xeb, 0x98, 0x24, 0x8c } };
        static const GUID guid_netease = { 0x6c43e92f, 0xb562, 0x4dab, { 0xc5, 0x04, 0xa0, 0x40, 0xfc, 0xa9, 0x35, 0x9d } };
        static const GUID guid_musixmatch = { 0x7d54fa30, 0xc673, 0x4ebc, { 0xd6, 0x15, 0xb1, 0x51, 0x0d, 0xba, 0x46, 0xae } };
        static const GUID guid_songlyrics = { 0x8e65fb41, 0xd784, 0x4fcd, { 0xe7, 0x26, 0xc2, 0x62, 0x1e, 0xcb, 0x57, 0xbf } };
//        static const GUID guid_autosearch = { 0x9f76fc52, 0xe895, 0x4ade, { 0xf8, 0x37, 0xd3, 0x73, 0x2f, 0xdc, 0x68, 0xc0 } };
//        static const GUID guid_fromfile = { 0xa087fd63, 0xf9a6, 0x4bef, { 0x09, 0x48, 0xe4, 0x84, 0x30, 0xed, 0x79, 0xd1 } };
        static const GUID guid_autosearch_save_file = { 0xb198fe74, 0x0ab7, 0x4cf0, { 0x1a, 0x59, 0xf5, 0x95, 0x41, 0xfe, 0x8a, 0xe2 } };
//        static const GUID guid_autosearch_save_tag = { 0xc2a9ff85, 0x1bc8, 0x4d01, { 0x2b, 0x6a, 0x06, 0xa6, 0x52, 0x0f, 0x9b, 0xf3 } };

        static const GUID guid_autosearch_save_file_silent = { 0xd3baffa6, 0x2cd9, 0x4e12, { 0x3c, 0x7b, 0x17, 0xb7, 0x63, 0x10, 0xac, 0x04 } };

        switch(p_index) {
            case autosearch_save_file: return guid_autosearch_save_file;
            case autosearch_save_file_silent: return guid_autosearch_save_file_silent;
//            case wack: return guid_wack;
            case qqmusic: return guid_qqmusic;
            case netease: return guid_netease;
            case musixmatch: return guid_musixmatch;
            case songlyrics: return guid_songlyrics;
//            case autosearch: return guid_autosearch;
//            case fromfile: return guid_fromfile;
//            case autosearch_save_tag: return guid_autosearch_save_tag;
            default: uBugCheck(); // should never happen unless somebody called us with invalid parameters - bail
        }

    }
    bool get_item_description(unsigned p_index,pfc::string_base & p_out) {
        switch(p_index) {
//            case wack:
//                p_out = "Search lyrics on AZLyrics.com";
//                return true;
            case qqmusic:
                p_out = "Search lyrics on QQ Music (synced lyrics)";
                return true;
            case netease:
                p_out = "Search lyrics on NetEase (synced lyrics)";
                return true;
            case musixmatch:
                p_out = "Search lyrics on Musixmatch (synced lyrics)";
                return true;
            case songlyrics:
                p_out = "Search lyrics on SongLyrics.com";
                return true;
//            case autosearch:
//                p_out = "Search all sources and return the best match";
//                return true;
//            case fromfile:
//                p_out = "Extract lyrics from file metadata tags";
//                return true;
            case autosearch_save_file:
                p_out = "Search all sources and save to .lrc file";
                return true;
            case autosearch_save_file_silent:
                p_out = "Search all sources and save to .lrc file (console output only)";
                return true;
//            case autosearch_save_tag:
//                p_out = "Search all sources and save to LYRICS tag";
//                return true;
            default:
                uBugCheck(); // should never happen unless somebody called us with invalid parameters - bail
        }
    }
};

static contextmenu_item_factory_t<myitem> g_myitem_factory;



static std::string bufferToString(char* buffer, int bufflen)
{
    std::string ret(buffer, bufflen);
    
    return ret;
}


static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}


static void load_html_document(const char* html, pugi::xml_document& doc)
{
    std::string lyric_text;
    
    // NOTE: TidyHtml will output debug messages to stderr by default on Windows, unless we define
    //       `DISABLE_DEBUG_LOG` when compiling the TidyHtml project.
    
    TidyBuffer output = {0};
    TidyBuffer errbuf = {0};
    int rc = -1;
    Bool ok;
    
    TidyDoc tdoc = tidyCreate(); // Initialize "document"
    // printf("Tidying:\t%s\n", str.c_str());
    
    ok = tidyOptSetBool(tdoc, TidyXmlOut, yes); // Convert to XHTML
    if (ok)
        rc = tidySetErrorBuffer(tdoc, &errbuf); // Capture diagnostics
    if (rc >= 0)
        rc = tidyParseString(tdoc, html); // Parse the input
    if (rc >= 0)
        rc = tidyCleanAndRepair(tdoc); // Tidy it up!
    if (rc >= 0)
        rc = tidyRunDiagnostics(tdoc); // Kvetch
    if (rc > 1)                        // If error, force output.
        rc = (tidyOptSetBool(tdoc, TidyForceOutput, yes) ? rc : -1);
    if (rc >= 0)
        rc = tidySaveBuffer(tdoc, &output); // Pretty Print
    
    
    if (rc >= 0)
    {
        if (rc > 0)
            console::print("\nDiagnostics:\n\n%s");
        //             printf("\nAnd here is the result:\n\n%s", output.bp);
    }
    else
        console::print("A severe error (%d) occurred.\n");
    
    doc.load_buffer(output.bp, output.size);
    tidyBufFree(&output);
    tidyBufFree(&errbuf);
    tidyRelease(tdoc);
}

static std::string_view trim_surrounding(std::string_view str, std::string_view trimset)
{
    size_t first_non_trimset = str.find_first_not_of(trimset);
    size_t last_non_trimset = str.find_last_not_of(trimset);
    
    if(first_non_trimset == std::string_view::npos)
    {
        return "";
    }
    size_t len = (last_non_trimset + 1) - first_non_trimset;
    return str.substr(first_non_trimset, len);
}

std::string_view trim_surrounding_whitespace(std::string_view str)
{
    return trim_surrounding(str, "\r\n ");
}

std::string_view trim_surrounding_line_endings(std::string_view str)
{
    return trim_surrounding(str, "\r\n");
}


static void add_all_text_to_string(std::string& output, const pugi::xml_node& node)
{
    // add_all_text_to_string_internal(output, pugi::xml_node(node));
    switch(node.type())
    {
        case pugi::node_null:
        case pugi::node_comment:
        case pugi::node_pi:
        case pugi::node_declaration:
        case pugi::node_doctype: return;
            
        case pugi::node_document:
        case pugi::node_element:
        {
            console::print("raw1");
            if(std::string_view(node.name()) == "br")
            {
                assert(node.children().empty());
                output += "\r\n";
                break;
            }
            
            for(pugi::xml_node child : node.children())
            {
                console::print("raw");
                add_all_text_to_string(output, child);
            }
        }
            break;
            
        case pugi::node_pcdata:
        case pugi::node_cdata:
        {
            // We assume the text is already UTF-8
            
            // Trim surrounding line-endings to get rid of the newlines in the HTML that don't affect rendering
            std::string node_text(trim_surrounding_line_endings(node.value()));
            
            // Sometimes tidyHtml inserts newlines in the middle of a line where there should just be a space.
            // Get rid of any carriage returns (in case they were added) and then replace
            // newlines in the middle of the text with spaces.
            node_text.erase(std::remove(node_text.begin(), node_text.end(), '\r'));
            std::replace(node_text.begin(), node_text.end(), '\n', ' ');
            
            output += node_text;
        }
            break;
    }
}


std::string_view trim_trailing_text_in_brackets(std::string_view str)
{
    std::string_view result = str;
    while(true)
    {
        size_t open_index = result.find_last_of("([{");
        if(open_index == std::string_view::npos)
        {
            break; // Nothing to trim
        }
        
        if(open_index == 0)
        {
            break; // Don't trim the entire string!
        }
        
        char opener = result[open_index];
        char closer = '\0';
        switch(opener)
        {
            case '[': closer = ']'; break;
            case '(': closer = ')'; break;
            case '{': closer = '}'; break;
        }
        assert(closer != '\0');
        
        size_t close_index = result.find_first_of(closer, open_index);
        if(close_index == std::string_view::npos)
        {
            break; // Unmatched open-bracket
        }
        
        result = result.substr(0, open_index);
    }
    
    return result;
}


std::string track_metadata(const file_info& track_info, std::string_view key)
{
    size_t value_index = track_info.meta_find_ex(key.data(), key.length());
    if(value_index == pfc::infinite_size)
    {
        return "";
    }
    
    size_t value_count = track_info.meta_enum_value_count(value_index);
    if(value_count == 0)
    {
        return "";
    }
    
    if(value_count > 1)
    {
        std::string err_msg;
        err_msg += "metadata tag ";
        err_msg += key;
        err_msg += " appears multiple times for ";
        const char* const err_tags[] = { "artist", "album", "title" };
        for(const char* err_tag : err_tags)
        {
            err_msg += "/";
            size_t err_index = track_info.meta_find(err_tag);
            if(err_index == pfc::infinite_size) continue;
            
            size_t err_tag_count = track_info.meta_enum_value_count(err_index);
            if(err_tag_count == 0) continue;
            const char* err_tag_value = track_info.meta_enum_value(err_index, 0);
        }
    }
    
    return track_info.meta_enum_value(value_index, 0);
}



std::string track_metadata(const metadb_v2_rec_t& track, std::string_view key)
{
    if(track.info == nullptr)
    {
        return {};
    }
    
    const file_info& track_info = track.info->info();
    return track_metadata(track_info, key);
}


std::string remove_chars_for_url( std::string_view input) {
    std::regex r("[^a-zA-Z]");
    std::string data = std::string(input);
    std::transform(data.begin(), data.end(), data.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    std::string result = std::regex_replace(std::string(data).c_str(), r, "");

    return result;
}

static std::string base64_decode(const std::string& encoded) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string decoded;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) {
        T[base64_chars[i]] = i;
    }

    int val = 0, valb = -8;
    for (unsigned char c : encoded) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded;
}

static bool is_ascii_alphanumeric(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

static std::string urlencode(std::string_view input)
{
    size_t inlen = input.length();
    std::string result;
    result.reserve(inlen * 3);

    for(size_t i = 0; i < inlen; i++)
    {
        if(is_ascii_alphanumeric(input[i]) || (input[i] == '-') || (input[i] == '_') || (input[i] == '.')
           || (input[i] == '~'))
        {
            result += input[i];
        }
        else if(input[i] == ' ')
        {
            result += "%20";
        }
        else
        {
            const auto nibble_to_hex = [](char c)
            {
                static char hex[] = "0123456789ABCDEF";
                return hex[c & 0xF];
            };

            char hi_nibble = ((input[i] >> 4) & 0xF);
            char lo_nibble = (input[i] & 0xF);
            result += '%';
            result += nibble_to_hex(hi_nibble);
            result += nibble_to_hex(lo_nibble);
        }
    }

    return result;
}


static void azlyrics_search(const metadb_v2_rec_t& track_info, pfc::string_formatter& message) {
    
    CURL *curl;
    CURLcode res;
    std::string readBuffer;
    curl = curl_easy_init();
    if (curl) {
        
        std::string url_artist = remove_chars_for_url(track_metadata(track_info, "artist"));
        std::string url_title = remove_chars_for_url(track_metadata(track_info, "title"));
        
        std::string url = "https://www.azlyrics.com/lyrics/" + url_artist + "/" + url_title + ".html";
        message << "getting : " << url.c_str();
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string lyric_text;
        
        
        pugi::xml_document doc;
        load_html_document(readBuffer.c_str(), doc);
        
        const pugi::xpath_node_set nodes = doc.select_nodes("//div/child::text()");
        
        
        for(auto& node: nodes)
        {
            lyric_text.append(node.node().value());
        }
        message << decode_html_entities(lyric_text).c_str() << "\n";
        //        console::print(lyric_text.c_str());

        //        message << readBuffer.c_str() << "\n";
    }
}


static std::string qqmusic_lookup(const std::string& song_mid, pfc::string_formatter& message) {
    CURL *curl;
    CURLcode res;
    std::string readBuffer;
    std::string lyrics;

    curl = curl_easy_init();
    if (curl) {
        std::string url = "http://c.y.qq.com/lyric/fcgi-bin/"
                          "fcg_query_lyric_new.fcg?g_tk=5381&format=json&inCharset=utf-8&outCharset=utf-8&songmid="
                          + song_mid;

        message << "Fetching lyrics from: " << url.c_str() << "\n";

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Referer: http://y.qq.com/portal/player.html");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res == CURLE_OK) {
            cJSON* json = cJSON_ParseWithLength(readBuffer.c_str(), readBuffer.length());
            if (json != nullptr && json->type == cJSON_Object) {
                cJSON* lyric_item = cJSON_GetObjectItem(json, "lyric");
                if (lyric_item != nullptr && lyric_item->type == cJSON_String) {
                    // Decode base64 lyrics
                    lyrics = base64_decode(lyric_item->valuestring);
                }
            }
            cJSON_Delete(json);
        }
    }

    return lyrics;
}


static void qqmusic_search(const metadb_v2_rec_t& track_info, pfc::string_formatter& message) {
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (curl) {
        std::string artist = track_metadata(track_info, "artist");
        std::string title = track_metadata(track_info, "title");

        std::string url = "https://c.y.qq.com/splcloud/fcgi-bin/smartbox_new.fcg?inCharset=utf-8&outCharset=utf-8&key="
                          + urlencode(artist) + '+' + urlencode(title);

        message << "Searching QQ Music: " << url.c_str() << "\n";

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Referer: http://y.qq.com/portal/player.html");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            message << "CURL error: " << curl_easy_strerror(res) << "\n";
            return;
        }

        // Parse JSON response to get song ID
        cJSON* json = cJSON_ParseWithLength(readBuffer.c_str(), readBuffer.length());
        if (json == nullptr || json->type != cJSON_Object) {
            message << "Failed to parse JSON response\n";
            cJSON_Delete(json);
            return;
        }

        cJSON* data_obj = cJSON_GetObjectItem(json, "data");
        if (data_obj == nullptr || data_obj->type != cJSON_Object) {
            message << "No 'data' in response\n";
            cJSON_Delete(json);
            return;
        }

        cJSON* song_obj = cJSON_GetObjectItem(data_obj, "song");
        if (song_obj == nullptr || song_obj->type != cJSON_Object) {
            message << "No 'song' in response\n";
            cJSON_Delete(json);
            return;
        }

        cJSON* song_arr = cJSON_GetObjectItem(song_obj, "itemlist");
        if (song_arr == nullptr || song_arr->type != cJSON_Array) {
            message << "No 'itemlist' in response\n";
            cJSON_Delete(json);
            return;
        }

        int song_count = cJSON_GetArraySize(song_arr);
        if (song_count <= 0) {
            message << "No songs found\n";
            cJSON_Delete(json);
            return;
        }

        // Get first song result
        cJSON* song_item = cJSON_GetArrayItem(song_arr, 0);
        if (song_item == nullptr || song_item->type != cJSON_Object) {
            message << "Invalid song item\n";
            cJSON_Delete(json);
            return;
        }

        // Get song mid (ID)
        cJSON* mid_item = cJSON_GetObjectItem(song_item, "mid");
        if (mid_item == nullptr || mid_item->type != cJSON_String) {
            message << "No song mid found\n";
            cJSON_Delete(json);
            return;
        }

        std::string song_mid = mid_item->valuestring;

        // Get song info for display
        cJSON* singer_item = cJSON_GetObjectItem(song_item, "singer");
        cJSON* name_item = cJSON_GetObjectItem(song_item, "name");

        if (singer_item && singer_item->type == cJSON_String) {
            message << "Artist: " << singer_item->valuestring << "\n";
        }
        if (name_item && name_item->type == cJSON_String) {
            message << "Title: " << name_item->valuestring << "\n";
        }
        message << "Song ID: " << song_mid.c_str() << "\n\n";

        cJSON_Delete(json);

        // Now lookup the lyrics using the song mid
        std::string lyrics = qqmusic_lookup(song_mid, message);
        if (!lyrics.empty()) {
            message << "--- Lyrics ---\n" << decode_html_entities(lyrics).c_str() << "\n";
        } else {
            message << "No lyrics found for this song\n";
        }
    }
}


static void RunQQMusic(metadb_handle_list_cref data) {
    pfc::string_formatter message;

    if (data.get_count() == 0) {
        message << "No track selected\n";
        popup_message::g_show(message, "QQ Music Lyrics");
        return;
    }

    metadb_handle_ptr track = data.get_item(0);
    const metadb_v2_rec_t track_info = get_full_metadata(track);
    qqmusic_search(track_info, message);

    popup_message::g_show(message, "QQ Music Lyrics");
}


// NetEase Music lyrics lookup by song ID
static std::string netease_lookup(const std::string& song_id, pfc::string_formatter& message) {
    std::string lyrics;
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (curl) {
        std::string url = "https://music.163.com/api/song/lyric?tv=-1&kv=-1&lv=-1&os=pc&id=" + song_id;
        message << "Fetching lyrics from: " << url.c_str() << "\n";

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Referer: https://music.163.com");
        headers = curl_slist_append(headers, "Cookie: appver=2.0.2");
        headers = curl_slist_append(headers, "charset: utf-8");
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        headers = curl_slist_append(headers, "X-Real-IP: 202.96.0.0");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
        res = curl_easy_perform(curl);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res == CURLE_OK) {
            cJSON* json = cJSON_ParseWithLength(readBuffer.c_str(), readBuffer.length());
            if (json != nullptr && json->type == cJSON_Object) {
                cJSON* lrc_item = cJSON_GetObjectItem(json, "lrc");
                if (lrc_item != nullptr && lrc_item->type == cJSON_Object) {
                    cJSON* lrc_lyric = cJSON_GetObjectItem(lrc_item, "lyric");
                    if (lrc_lyric != nullptr && lrc_lyric->type == cJSON_String) {
                        lyrics = lrc_lyric->valuestring;
                    }
                }
            }
            cJSON_Delete(json);
        }
    }

    return lyrics;
}


// NetEase Music search
static void netease_search(const metadb_v2_rec_t& track_info, pfc::string_formatter& message) {
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (curl) {
        std::string artist = track_metadata(track_info, "artist");
        std::string title = track_metadata(track_info, "title");

        std::string url = "https://music.163.com/api/search/get?s="
                          + urlencode(artist) + '+' + urlencode(title)
                          + "&type=1&offset=0&sub=false&limit=5";

        message << "Searching NetEase: " << url.c_str() << "\n";

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Referer: https://music.163.com");
        headers = curl_slist_append(headers, "Cookie: appver=2.0.2");
        headers = curl_slist_append(headers, "charset: utf-8");
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        headers = curl_slist_append(headers, "X-Real-IP: 202.96.0.0");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
        res = curl_easy_perform(curl);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            message << "CURL error: " << curl_easy_strerror(res) << "\n";
            return;
        }

        // Parse JSON response to get song ID
        cJSON* json = cJSON_ParseWithLength(readBuffer.c_str(), readBuffer.length());
        if (json == nullptr || json->type != cJSON_Object) {
            message << "Failed to parse JSON response\n";
            cJSON_Delete(json);
            return;
        }

        cJSON* result_obj = cJSON_GetObjectItem(json, "result");
        if (result_obj == nullptr || result_obj->type != cJSON_Object) {
            message << "No 'result' in response\n";
            cJSON_Delete(json);
            return;
        }

        cJSON* song_arr = cJSON_GetObjectItem(result_obj, "songs");
        if (song_arr == nullptr || song_arr->type != cJSON_Array) {
            message << "No 'songs' in response\n";
            cJSON_Delete(json);
            return;
        }

        int song_count = cJSON_GetArraySize(song_arr);
        if (song_count <= 0) {
            message << "No songs found\n";
            cJSON_Delete(json);
            return;
        }

        // Get first song result
        cJSON* song_item = cJSON_GetArrayItem(song_arr, 0);
        if (song_item == nullptr || song_item->type != cJSON_Object) {
            message << "Invalid song item\n";
            cJSON_Delete(json);
            return;
        }

        // Get song ID (numeric)
        cJSON* id_item = cJSON_GetObjectItem(song_item, "id");
        if (id_item == nullptr || id_item->type != cJSON_Number) {
            message << "No song ID found\n";
            cJSON_Delete(json);
            return;
        }

        std::string song_id = std::to_string((int64_t)id_item->valuedouble);

        // Get song info for display
        cJSON* title_item = cJSON_GetObjectItem(song_item, "name");
        if (title_item && title_item->type == cJSON_String) {
            message << "Title: " << title_item->valuestring << "\n";
        }

        // Get artist from artists array
        cJSON* artist_list = cJSON_GetObjectItem(song_item, "artists");
        if (artist_list && artist_list->type == cJSON_Array && cJSON_GetArraySize(artist_list) > 0) {
            cJSON* first_artist = cJSON_GetArrayItem(artist_list, 0);
            if (first_artist && first_artist->type == cJSON_Object) {
                cJSON* artist_name = cJSON_GetObjectItem(first_artist, "name");
                if (artist_name && artist_name->type == cJSON_String) {
                    message << "Artist: " << artist_name->valuestring << "\n";
                }
            }
        }

        message << "Song ID: " << song_id.c_str() << "\n\n";

        cJSON_Delete(json);

        // Now lookup the lyrics using the song ID
        std::string lyrics = netease_lookup(song_id, message);
        if (!lyrics.empty()) {
            message << "--- Lyrics ---\n" << decode_html_entities(lyrics).c_str() << "\n";
        } else {
            message << "No lyrics found for this song\n";
        }
    }
}


static void RunNetEase(metadb_handle_list_cref data) {
    pfc::string_formatter message;

    if (data.get_count() == 0) {
        message << "No track selected\n";
        popup_message::g_show(message, "NetEase Lyrics");
        return;
    }

    metadb_handle_ptr track = data.get_item(0);
    const metadb_v2_rec_t track_info = get_full_metadata(track);
    netease_search(track_info, message);

    popup_message::g_show(message, "NetEase Lyrics");
}


// Musixmatch API constants
static const char* MUSIXMATCH_API_URL = "https://apic-desktop.musixmatch.com/ws/1.1/";
static const char* MUSIXMATCH_COMMON_PARAMS = "user_language=en&app_id=web-desktop-app-v1.0";

// Musixmatch token - hardcoded for simplicity (in production, should be fetched dynamically)
// This token may expire and need to be refreshed
static std::string g_musixmatch_token = "";

// Fetch a new Musixmatch token
static std::string musixmatch_get_token(pfc::string_formatter& message) {
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (!curl) {
        return "";
    }

    std::string url = std::string(MUSIXMATCH_API_URL) + "token.get?" + MUSIXMATCH_COMMON_PARAMS;
    message << "Fetching Musixmatch token from: " << url.c_str() << "\n";

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "cookie: AWSELBCORS=0; AWSELB=0");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        message << "Failed to get token: " << curl_easy_strerror(res) << "\n";
        return "";
    }

    cJSON* json = cJSON_ParseWithLength(readBuffer.c_str(), readBuffer.length());
    if (json == nullptr || json->type != cJSON_Object) {
        message << "Failed to parse token response\n";
        cJSON_Delete(json);
        return "";
    }

    cJSON* json_message = cJSON_GetObjectItem(json, "message");
    cJSON* json_body = cJSON_GetObjectItem(json_message, "body");
    cJSON* json_token = cJSON_GetObjectItem(json_body, "user_token");

    std::string token;
    if (json_token && json_token->type == cJSON_String) {
        token = json_token->valuestring;
        message << "Got token: " << token.substr(0, 10).c_str() << "...\n";
    } else {
        message << "Token not found in response\n";
    }

    cJSON_Delete(json);
    return token;
}

// Musixmatch lyrics lookup by track ID (synced)
static std::string musixmatch_lookup_synced(const std::string& track_id, const std::string& token, pfc::string_formatter& message) {
    std::string lyrics;
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (!curl) {
        return "";
    }

    std::string url = std::string(MUSIXMATCH_API_URL) + "track.subtitle.get?" + MUSIXMATCH_COMMON_PARAMS
                      + "&commontrack_id=" + track_id + "&usertoken=" + token;
    message << "Fetching synced lyrics from Musixmatch...\n";

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "cookie: AWSELBCORS=0; AWSELB=0");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        message << "CURL error: " << curl_easy_strerror(res) << "\n";
        return "";
    }

    cJSON* json = cJSON_ParseWithLength(readBuffer.c_str(), readBuffer.length());
    if (json != nullptr && json->type == cJSON_Object) {
        cJSON* json_message = cJSON_GetObjectItem(json, "message");
        cJSON* json_body = cJSON_GetObjectItem(json_message, "body");
        cJSON* json_subtitle = cJSON_GetObjectItem(json_body, "subtitle");
        cJSON* json_subtitle_body = cJSON_GetObjectItem(json_subtitle, "subtitle_body");
        if (json_subtitle_body && json_subtitle_body->type == cJSON_String && strlen(json_subtitle_body->valuestring) > 0) {
            lyrics = json_subtitle_body->valuestring;
        }
    }
    cJSON_Delete(json);

    return lyrics;
}

// Musixmatch lyrics lookup by track ID (unsynced)
static std::string musixmatch_lookup_unsynced(const std::string& track_id, const std::string& token, pfc::string_formatter& message) {
    std::string lyrics;
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (!curl) {
        return "";
    }

    std::string url = std::string(MUSIXMATCH_API_URL) + "track.lyrics.get?" + MUSIXMATCH_COMMON_PARAMS
                      + "&commontrack_id=" + track_id + "&usertoken=" + token;
    message << "Fetching unsynced lyrics from Musixmatch...\n";

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "cookie: AWSELBCORS=0; AWSELB=0");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        message << "CURL error: " << curl_easy_strerror(res) << "\n";
        return "";
    }

    cJSON* json = cJSON_ParseWithLength(readBuffer.c_str(), readBuffer.length());
    if (json != nullptr && json->type == cJSON_Object) {
        cJSON* json_message = cJSON_GetObjectItem(json, "message");
        cJSON* json_body = cJSON_GetObjectItem(json_message, "body");
        cJSON* json_lyrics = cJSON_GetObjectItem(json_body, "lyrics");
        cJSON* json_lyrics_body = cJSON_GetObjectItem(json_lyrics, "lyrics_body");
        if (json_lyrics_body && json_lyrics_body->type == cJSON_String && strlen(json_lyrics_body->valuestring) > 0) {
            lyrics = json_lyrics_body->valuestring;
        }
    }
    cJSON_Delete(json);

    return lyrics;
}

// Musixmatch search
static void musixmatch_search(const metadb_v2_rec_t& track_info, pfc::string_formatter& message) {
    // Get or refresh token
    if (g_musixmatch_token.empty()) {
        g_musixmatch_token = musixmatch_get_token(message);
        if (g_musixmatch_token.empty()) {
            message << "Failed to get Musixmatch token\n";
            return;
        }
    }

    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (!curl) {
        return;
    }

    std::string artist = track_metadata(track_info, "artist");
    std::string album = track_metadata(track_info, "album");
    std::string title = track_metadata(track_info, "title");

    std::string url = std::string(MUSIXMATCH_API_URL) + "track.search?" + MUSIXMATCH_COMMON_PARAMS
                      + "&subtitle_format=lrc"
                      + "&q_artist=" + urlencode(artist)
                      + "&q_album=" + urlencode(album)
                      + "&q_track=" + urlencode(title)
                      + "&usertoken=" + g_musixmatch_token;

    message << "Searching Musixmatch for: " << artist.c_str() << " - " << title.c_str() << "\n";

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "cookie: AWSELBCORS=0; AWSELB=0");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        message << "CURL error: " << curl_easy_strerror(res) << "\n";
        return;
    }

    // Parse JSON response
    cJSON* json = cJSON_ParseWithLength(readBuffer.c_str(), readBuffer.length());
    if (json == nullptr || json->type != cJSON_Object) {
        message << "Failed to parse JSON response\n";
        cJSON_Delete(json);
        return;
    }

    cJSON* json_message = cJSON_GetObjectItem(json, "message");
    cJSON* json_body = cJSON_GetObjectItem(json_message, "body");
    cJSON* json_tracklist = cJSON_GetObjectItem(json_body, "track_list");

    if (!cJSON_IsArray(json_tracklist) || cJSON_GetArraySize(json_tracklist) == 0) {
        message << "No tracks found\n";
        cJSON_Delete(json);
        return;
    }

    // Get first track
    cJSON* json_track = cJSON_GetArrayItem(json_tracklist, 0);
    cJSON* json_tracktrack = cJSON_GetObjectItem(json_track, "track");

    cJSON* json_artist = cJSON_GetObjectItem(json_tracktrack, "artist_name");
    cJSON* json_title_item = cJSON_GetObjectItem(json_tracktrack, "track_name");
    cJSON* json_hassubtitles = cJSON_GetObjectItem(json_tracktrack, "has_subtitles");
    cJSON* json_haslyrics = cJSON_GetObjectItem(json_tracktrack, "has_lyrics");
    cJSON* json_trackid = cJSON_GetObjectItem(json_tracktrack, "commontrack_id");

    if (json_artist && json_artist->type == cJSON_String) {
        message << "Artist: " << json_artist->valuestring << "\n";
    }
    if (json_title_item && json_title_item->type == cJSON_String) {
        message << "Title: " << json_title_item->valuestring << "\n";
    }

    if (!json_trackid || json_trackid->type != cJSON_Number) {
        message << "No track ID found\n";
        cJSON_Delete(json);
        return;
    }

    std::string track_id = std::to_string(json_trackid->valueint);
    message << "Track ID: " << track_id.c_str() << "\n";

    bool has_subtitles = json_hassubtitles && json_hassubtitles->type == cJSON_Number && json_hassubtitles->valueint != 0;
    bool has_lyrics = json_haslyrics && json_haslyrics->type == cJSON_Number && json_haslyrics->valueint != 0;

    message << "Has synced lyrics: " << (has_subtitles ? "yes" : "no") << "\n";
    message << "Has unsynced lyrics: " << (has_lyrics ? "yes" : "no") << "\n\n";

    cJSON_Delete(json);

    // Try to get synced lyrics first, fall back to unsynced
    std::string lyrics;
    if (has_subtitles) {
        lyrics = musixmatch_lookup_synced(track_id, g_musixmatch_token, message);
    }
    if (lyrics.empty() && has_lyrics) {
        lyrics = musixmatch_lookup_unsynced(track_id, g_musixmatch_token, message);
    }

    if (!lyrics.empty()) {
        message << "--- Lyrics ---\n" << decode_html_entities(lyrics).c_str() << "\n";
    } else {
        message << "No lyrics found for this song\n";
    }
}


static void RunMusixmatch(metadb_handle_list_cref data) {
    pfc::string_formatter message;

    if (data.get_count() == 0) {
        message << "No track selected\n";
        popup_message::g_show(message, "Musixmatch Lyrics");
        return;
    }

    metadb_handle_ptr track = data.get_item(0);
    const metadb_v2_rec_t track_info = get_full_metadata(track);
    musixmatch_search(track_info, message);

    popup_message::g_show(message, "Musixmatch Lyrics");
}


// Helper function to create URL-friendly string for SongLyrics.com
static std::string songlyrics_remove_chars_for_url(const std::string& input) {
    std::string output;
    output.reserve(input.length() + 3);

    for (char c : input) {
        if (is_ascii_alphanumeric(c)) {
            output += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        } else if (c == ' ' || c == '-') {
            output += '-';
        } else if (c == '&') {
            output += "and";
        } else if (c == '@') {
            output += "at";
        }
        // Skip all other characters
    }

    return output;
}

// SongLyrics.com search
static void songlyrics_search(const metadb_v2_rec_t& track_info, pfc::string_formatter& message) {
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (!curl) {
        return;
    }

    std::string artist = track_metadata(track_info, "artist");
    std::string title = track_metadata(track_info, "title");

    // Construct URL: https://songlyrics.com/artist-name/song-title-lyrics
    std::string url = "https://www.songlyrics.com/"
                      + songlyrics_remove_chars_for_url(artist) + "/"
                      + songlyrics_remove_chars_for_url(title) + "-lyrics/";

    message << "Searching SongLyrics.com: " << url.c_str() << "\n";

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)");
    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        message << "CURL error: " << curl_easy_strerror(res) << "\n";
        return;
    }

    // Parse HTML to find lyrics in <p id="songLyricsDiv">
    pugi::xml_document doc;
    load_html_document(readBuffer.c_str(), doc);

    // Try to find the lyrics div
    pugi::xpath_query query_lyricdiv("//p[@id='songLyricsDiv']");
    pugi::xpath_node_set lyricdivs = query_lyricdiv.evaluate_node_set(doc);

    if (lyricdivs.empty()) {
        message << "Could not find lyrics on page (lyrics div not found)\n";
        return;
    }

    // Extract text from the lyrics div
    std::string lyrics;
    pugi::xml_node lyrics_node = lyricdivs.first().node();

    // Recursively get all text content
    std::function<void(pugi::xml_node)> extract_text = [&](pugi::xml_node node) {
        for (pugi::xml_node child = node.first_child(); child; child = child.next_sibling()) {
            if (child.type() == pugi::node_pcdata) {
                lyrics += child.value();
            } else if (child.type() == pugi::node_element) {
                std::string name = child.name();
                if (name == "br") {
                    lyrics += "\n";
                } else {
                    extract_text(child);
                }
            }
        }
    };

    extract_text(lyrics_node);

    // Check for placeholder text "We do not have the lyrics for X yet."
    if (lyrics.find("We do not have the lyrics for") != std::string::npos) {
        message << "Lyrics not available on SongLyrics.com\n";
        return;
    }

    // Trim whitespace
    size_t start = lyrics.find_first_not_of(" \t\n\r");
    size_t end = lyrics.find_last_not_of(" \t\n\r");
    if (start != std::string::npos && end != std::string::npos) {
        lyrics = lyrics.substr(start, end - start + 1);
    }

    if (!lyrics.empty()) {
        message << "Artist: " << artist.c_str() << "\n";
        message << "Title: " << title.c_str() << "\n\n";
        message << "--- Lyrics ---\n" << decode_html_entities(lyrics).c_str() << "\n";
    } else {
        message << "No lyrics found for this song\n";
    }
}


static void RunSongLyrics(metadb_handle_list_cref data) {
    pfc::string_formatter message;

    if (data.get_count() == 0) {
        message << "No track selected\n";
        popup_message::g_show(message, "SongLyrics");
        return;
    }

    metadb_handle_ptr track = data.get_item(0);
    const metadb_v2_rec_t track_info = get_full_metadata(track);
    songlyrics_search(track_info, message);

    popup_message::g_show(message, "SongLyrics");
}


// Structure to hold lyrics search result
struct LyricsResult {
    std::string source_name;
    std::string lyrics;
    size_t length;
};

// Helper function to extract just the lyrics portion from QQ Music
static std::string qqmusic_search_lyrics_only(const metadb_v2_rec_t& track_info) {
    CURL *curl = curl_easy_init();
    if (!curl) return "";

    std::string readBuffer;
    std::string artist = track_metadata(track_info, "artist");
    std::string title = track_metadata(track_info, "title");

    std::string url = "https://c.y.qq.com/splcloud/fcgi-bin/smartbox_new.fcg?inCharset=utf-8&outCharset=utf-8&key="
                      + urlencode(artist) + '+' + urlencode(title);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Referer: http://y.qq.com/portal/player.html");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return "";

    cJSON* json = cJSON_ParseWithLength(readBuffer.c_str(), readBuffer.length());
    if (!json) return "";

    std::string song_mid;
    cJSON* data_obj = cJSON_GetObjectItem(json, "data");
    if (data_obj) {
        cJSON* song_obj = cJSON_GetObjectItem(data_obj, "song");
        if (song_obj) {
            cJSON* song_arr = cJSON_GetObjectItem(song_obj, "itemlist");
            if (song_arr && cJSON_GetArraySize(song_arr) > 0) {
                cJSON* song_item = cJSON_GetArrayItem(song_arr, 0);
                cJSON* mid_item = cJSON_GetObjectItem(song_item, "mid");
                if (mid_item && mid_item->type == cJSON_String) {
                    song_mid = mid_item->valuestring;
                }
            }
        }
    }
    cJSON_Delete(json);

    if (song_mid.empty()) return "";

    // Lookup lyrics
    pfc::string_formatter dummy;
    return qqmusic_lookup(song_mid, dummy);
}

// Helper function to extract just the lyrics portion from NetEase
static std::string netease_search_lyrics_only(const metadb_v2_rec_t& track_info) {
    CURL *curl = curl_easy_init();
    if (!curl) return "";

    std::string readBuffer;
    std::string artist = track_metadata(track_info, "artist");
    std::string title = track_metadata(track_info, "title");

    std::string url = "https://music.163.com/api/search/get?s="
                      + urlencode(artist) + '+' + urlencode(title)
                      + "&type=1&offset=0&sub=false&limit=5";

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Referer: https://music.163.com");
    headers = curl_slist_append(headers, "Cookie: appver=2.0.2");
    headers = curl_slist_append(headers, "charset: utf-8");
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    headers = curl_slist_append(headers, "X-Real-IP: 202.96.0.0");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return "";

    cJSON* json = cJSON_ParseWithLength(readBuffer.c_str(), readBuffer.length());
    if (!json) return "";

    std::string song_id;
    cJSON* result_obj = cJSON_GetObjectItem(json, "result");
    if (result_obj) {
        cJSON* song_arr = cJSON_GetObjectItem(result_obj, "songs");
        if (song_arr && cJSON_GetArraySize(song_arr) > 0) {
            cJSON* song_item = cJSON_GetArrayItem(song_arr, 0);
            cJSON* id_item = cJSON_GetObjectItem(song_item, "id");
            if (id_item && id_item->type == cJSON_Number) {
                song_id = std::to_string((int64_t)id_item->valuedouble);
            }
        }
    }
    cJSON_Delete(json);

    if (song_id.empty()) return "";

    // Lookup lyrics
    pfc::string_formatter dummy;
    return netease_lookup(song_id, dummy);
}

// Helper function to extract just the lyrics portion from Musixmatch
static std::string musixmatch_search_lyrics_only(const metadb_v2_rec_t& track_info) {
    // Get or refresh token
    if (g_musixmatch_token.empty()) {
        pfc::string_formatter dummy;
        g_musixmatch_token = musixmatch_get_token(dummy);
        if (g_musixmatch_token.empty()) return "";
    }

    CURL *curl = curl_easy_init();
    if (!curl) return "";

    std::string readBuffer;
    std::string artist = track_metadata(track_info, "artist");
    std::string album = track_metadata(track_info, "album");
    std::string title = track_metadata(track_info, "title");

    std::string url = std::string(MUSIXMATCH_API_URL) + "track.search?" + MUSIXMATCH_COMMON_PARAMS
                      + "&subtitle_format=lrc"
                      + "&q_artist=" + urlencode(artist)
                      + "&q_album=" + urlencode(album)
                      + "&q_track=" + urlencode(title)
                      + "&usertoken=" + g_musixmatch_token;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "cookie: AWSELBCORS=0; AWSELB=0");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return "";

    cJSON* json = cJSON_ParseWithLength(readBuffer.c_str(), readBuffer.length());
    if (!json) return "";

    std::string track_id;
    bool has_subtitles = false;
    bool has_lyrics = false;

    cJSON* json_message = cJSON_GetObjectItem(json, "message");
    cJSON* json_body = cJSON_GetObjectItem(json_message, "body");
    cJSON* json_tracklist = cJSON_GetObjectItem(json_body, "track_list");

    if (cJSON_IsArray(json_tracklist) && cJSON_GetArraySize(json_tracklist) > 0) {
        cJSON* json_track = cJSON_GetArrayItem(json_tracklist, 0);
        cJSON* json_tracktrack = cJSON_GetObjectItem(json_track, "track");
        cJSON* json_trackid = cJSON_GetObjectItem(json_tracktrack, "commontrack_id");
        cJSON* json_hassubtitles = cJSON_GetObjectItem(json_tracktrack, "has_subtitles");
        cJSON* json_haslyrics = cJSON_GetObjectItem(json_tracktrack, "has_lyrics");

        if (json_trackid && json_trackid->type == cJSON_Number) {
            track_id = std::to_string(json_trackid->valueint);
        }
        has_subtitles = json_hassubtitles && json_hassubtitles->valueint != 0;
        has_lyrics = json_haslyrics && json_haslyrics->valueint != 0;
    }
    cJSON_Delete(json);

    if (track_id.empty()) return "";

    pfc::string_formatter dummy;
    std::string lyrics;
    if (has_subtitles) {
        lyrics = musixmatch_lookup_synced(track_id, g_musixmatch_token, dummy);
    }
    if (lyrics.empty() && has_lyrics) {
        lyrics = musixmatch_lookup_unsynced(track_id, g_musixmatch_token, dummy);
    }
    return lyrics;
}

// Helper function to extract just the lyrics portion from SongLyrics.com
static std::string songlyrics_search_lyrics_only(const metadb_v2_rec_t& track_info) {
    CURL *curl = curl_easy_init();
    if (!curl) return "";

    std::string readBuffer;
    std::string artist = track_metadata(track_info, "artist");
    std::string title = track_metadata(track_info, "title");

    std::string url = "https://www.songlyrics.com/"
                      + songlyrics_remove_chars_for_url(artist) + "/"
                      + songlyrics_remove_chars_for_url(title) + "-lyrics/";

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)");
    CURLcode res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return "";

    pugi::xml_document doc;
    load_html_document(readBuffer.c_str(), doc);

    pugi::xpath_query query_lyricdiv("//p[@id='songLyricsDiv']");
    pugi::xpath_node_set lyricdivs = query_lyricdiv.evaluate_node_set(doc);

    if (lyricdivs.empty()) return "";

    std::string lyrics;
    pugi::xml_node lyrics_node = lyricdivs.first().node();

    std::function<void(pugi::xml_node)> extract_text = [&](pugi::xml_node node) {
        for (pugi::xml_node child = node.first_child(); child; child = child.next_sibling()) {
            if (child.type() == pugi::node_pcdata) {
                lyrics += child.value();
            } else if (child.type() == pugi::node_element) {
                std::string name = child.name();
                if (name == "br") {
                    lyrics += "\n";
                } else {
                    extract_text(child);
                }
            }
        }
    };

    extract_text(lyrics_node);

    if (lyrics.find("We do not have the lyrics for") != std::string::npos) {
        return "";
    }

    size_t start = lyrics.find_first_not_of(" \t\n\r");
    size_t end = lyrics.find_last_not_of(" \t\n\r");
    if (start != std::string::npos && end != std::string::npos) {
        lyrics = lyrics.substr(start, end - start + 1);
    }

    return lyrics;
}

// Auto search - iterate through all sources and return best match
static void RunAutoSearch(metadb_handle_list_cref data) {
    pfc::string_formatter message;

    if (data.get_count() == 0) {
        message << "No track selected\n";
        popup_message::g_show(message, "Auto Search");
        return;
    }

    metadb_handle_ptr track = data.get_item(0);
    const metadb_v2_rec_t track_info = get_full_metadata(track);

    auto [lyrics, source_name] = auto_search_get_best_lyrics(track_info, track, message);

    if (lyrics.empty()) {
        message << "No lyrics found from any source.\n";
    } else {
        message << "Best match from: " << source_name.c_str() << " (" << lyrics.length() << " chars)\n\n";
        message << "--- Lyrics ---\n" << lyrics.c_str() << "\n";
    }

    popup_message::g_show(message, "Auto Search");
}


// Extract lyrics from file metadata
static void RunFromFile(metadb_handle_list_cref data) {
    pfc::string_formatter message;

    if (data.get_count() == 0) {
        message << "No track selected\n";
        popup_message::g_show(message, "From File Metadata");
        return;
    }

    metadb_handle_ptr track = data.get_item(0);
    const metadb_v2_rec_t track_info = get_full_metadata(track);

    std::string artist = track_metadata(track_info, "artist");
    std::string title = track_metadata(track_info, "title");

    message << "Track: " << artist.c_str() << " - " << title.c_str() << "\n\n";

    // Try various lyrics tag names (different formats use different tag names)
    const char* lyrics_tags[] = {
        "lyrics",           // Common tag
        "LYRICS",           // Uppercase variant
        "UNSYNCEDLYRICS",   // ID3v2 unsynced lyrics
        "UNSYNCED LYRICS",  // Alternative
        "SYNCEDLYRICS",     // ID3v2 synced lyrics
        "SYLT",             // ID3v2 synced lyrics frame
        "USLT",             // ID3v2 unsynced lyrics frame
    };

    std::string found_lyrics;
    std::string found_tag;

    for (const char* tag : lyrics_tags) {
        std::string lyrics = track_metadata(track_info, tag);
        if (!lyrics.empty()) {
            found_lyrics = lyrics;
            found_tag = tag;
            break;
        }
    }

    if (!found_lyrics.empty()) {
        message << "Found lyrics in tag: " << found_tag.c_str() << "\n";
        message << "Length: " << found_lyrics.length() << " chars\n\n";
        message << "--- Lyrics ---\n" << decode_html_entities(found_lyrics).c_str() << "\n";
    } else {
        message << "No lyrics found in file metadata.\n\n";
        message << "Searched tags: lyrics, LYRICS, UNSYNCEDLYRICS, UNSYNCED LYRICS, SYNCEDLYRICS, SYLT, USLT\n";
    }

    popup_message::g_show(message, "From File Metadata");
}


// Helper: Check for cached lyrics in metadata tags
static std::string get_cached_lyrics_from_tag(const metadb_v2_rec_t& track_info) {
    const char* lyrics_tags[] = {
        "lyrics", "LYRICS", "UNSYNCEDLYRICS", "UNSYNCED LYRICS",
        "SYNCEDLYRICS", "SYLT", "USLT"
    };

    for (const char* tag : lyrics_tags) {
        std::string lyrics = track_metadata(track_info, tag);
        if (!lyrics.empty()) {
            return lyrics;
        }
    }
    return "";
}

// Lyrics cache folder path
static const std::string LYRICS_CACHE_FOLDER = std::string(getenv("HOME")) + "/Music/LyricsCache/";

// Helper: Sanitize filename by removing invalid characters
static std::string sanitize_filename(const std::string& name) {
    std::string result;
    for (char c : name) {
        // Replace invalid filename characters with underscore
        if (c == '/' || c == '\\' || c == ':' || c == '*' || c == '?' ||
            c == '"' || c == '<' || c == '>' || c == '|') {
            result += '_';
        } else {
            result += c;
        }
    }
    // Trim leading/trailing spaces
    size_t start = result.find_first_not_of(' ');
    size_t end = result.find_last_not_of(' ');
    if (start != std::string::npos && end != std::string::npos) {
        result = result.substr(start, end - start + 1);
    }
    return result;
}

// Helper: Get lyrics cache path for a track
static std::string get_lyrics_cache_path(const metadb_v2_rec_t& track_info, const std::string& ext = ".lrc") {
    std::string artist = track_metadata(track_info, "artist");
    std::string title = track_metadata(track_info, "title");

    if (artist.empty() || title.empty()) {
        return "";
    }

    std::string filename = sanitize_filename(artist) + " - " + sanitize_filename(title) + ext;
    return LYRICS_CACHE_FOLDER + filename;
}

// Helper: Check for cached lyrics in .lrc file
static std::string get_cached_lyrics_from_file(metadb_handle_ptr track) {
    const metadb_v2_rec_t track_info = get_full_metadata(track);

    // Try .lrc first, then .txt
    std::vector<std::string> extensions = {".lrc", ".txt"};
    for (const auto& ext : extensions) {
        std::string lyrics_path = get_lyrics_cache_path(track_info, ext);
        if (lyrics_path.empty()) {
            continue;
        }

        std::ifstream infile(lyrics_path, std::ios::in | std::ios::binary);
        if (infile.is_open()) {
            std::string lyrics((std::istreambuf_iterator<char>(infile)),
                               std::istreambuf_iterator<char>());
            infile.close();
            if (!lyrics.empty()) {
                return lyrics;
            }
        }
    }

    return "";
}

// Helper: Get best lyrics from all sources (returns lyrics string and source name)
// Checks cached/local sources first before searching online
static std::pair<std::string, std::string> auto_search_get_best_lyrics(const metadb_v2_rec_t& track_info, metadb_handle_ptr track, pfc::string_formatter& message) {
    std::string artist = track_metadata(track_info, "artist");
    std::string title = track_metadata(track_info, "title");

    message << "Searching for: " << artist.c_str() << " - " << title.c_str() << "\n\n";

    // Check cached sources first
    message << "=== Checking Local/Cached Sources ===\n";

    // Check metadata tags
    message << "Checking metadata tags... ";
    std::string tag_lyrics = get_cached_lyrics_from_tag(track_info);
    if (!tag_lyrics.empty()) {
        message << "FOUND (" << tag_lyrics.length() << " chars)\n";
        message << "[Using cached lyrics from metadata tag]\n";
        return {decode_html_entities(tag_lyrics), "Metadata Tag (cached)"};
    }
    message << "not found\n";

    // Check .lrc/.txt files
    message << "Checking .lrc/.txt files... ";
    std::string file_lyrics = get_cached_lyrics_from_file(track);
    if (!file_lyrics.empty()) {
        message << "FOUND (" << file_lyrics.length() << " chars)\n";
        message << "[Using cached lyrics from file]\n";
        return {decode_html_entities(file_lyrics), "Local File (cached)"};
    }
    message << "not found\n";

    message << "\n=== Searching Online Sources ===\n";

    std::vector<LyricsResult> results;

    // Try each online source
    message << "Searching QQ Music... ";
    std::string qq_lyrics = qqmusic_search_lyrics_only(track_info);
    if (!qq_lyrics.empty()) {
        results.push_back({"QQ Music", qq_lyrics, qq_lyrics.length()});
        message << "found (" << qq_lyrics.length() << " chars)\n";
    } else {
        message << "not found\n";
    }

    message << "Searching NetEase... ";
    std::string netease_lyrics = netease_search_lyrics_only(track_info);
    if (!netease_lyrics.empty()) {
        results.push_back({"NetEase", netease_lyrics, netease_lyrics.length()});
        message << "found (" << netease_lyrics.length() << " chars)\n";
    } else {
        message << "not found\n";
    }

    message << "Searching Musixmatch... ";
    std::string musixmatch_lyrics = musixmatch_search_lyrics_only(track_info);
    if (!musixmatch_lyrics.empty()) {
        results.push_back({"Musixmatch", musixmatch_lyrics, musixmatch_lyrics.length()});
        message << "found (" << musixmatch_lyrics.length() << " chars)\n";
    } else {
        message << "not found\n";
    }

    message << "Searching SongLyrics.com... ";
    std::string songlyrics_lyrics = songlyrics_search_lyrics_only(track_info);
    if (!songlyrics_lyrics.empty()) {
        results.push_back({"SongLyrics.com", songlyrics_lyrics, songlyrics_lyrics.length()});
        message << "found (" << songlyrics_lyrics.length() << " chars)\n";
    } else {
        message << "not found\n";
    }

    message << "\n";

    if (results.empty()) {
        return {"", ""};
    }

    // Find the result with the longest lyrics
    auto best = std::max_element(results.begin(), results.end(),
        [](const LyricsResult& a, const LyricsResult& b) {
            return a.length < b.length;
        });

    return {decode_html_entities(best->lyrics), best->source_name};
}


// Save lyrics to .lrc file in the lyrics cache folder
static bool save_lyrics_to_file(metadb_handle_ptr track, const std::string& lyrics, pfc::string_formatter& message) {
    const metadb_v2_rec_t track_info = get_full_metadata(track);

    std::string lrc_path = get_lyrics_cache_path(track_info, ".lrc");
    if (lrc_path.empty()) {
        message << "Error: Could not determine lyrics path (missing artist or title)\n";
        return false;
    }

    // Create cache folder if it doesn't exist
    std::string mkdir_cmd = "mkdir -p \"" + LYRICS_CACHE_FOLDER + "\"";
    system(mkdir_cmd.c_str());

    message << "Saving to: " << lrc_path.c_str() << "\n";

    // Write the file
    std::ofstream outfile(lrc_path, std::ios::out | std::ios::binary);
    if (!outfile.is_open()) {
        message << "Error: Could not open file for writing\n";
        return false;
    }

    outfile.write(lyrics.c_str(), lyrics.length());
    outfile.close();

    if (outfile.fail()) {
        message << "Error: Failed to write to file\n";
        return false;
    }

    message << "Successfully saved " << lyrics.length() << " bytes\n";
    return true;
}


// Save lyrics to metadata tag
static bool save_lyrics_to_tag(metadb_handle_ptr track, const std::string& lyrics, pfc::string_formatter& message) {
    message << "Saving to LYRICS tag...\n";

    const std::string tag_name = "LYRICS";

    // Create the filter to update the tag
    const auto update_meta_tag = [&tag_name, &lyrics](trackRef /*location*/, t_filestats /*stats*/, file_info& info) {
        info.meta_set_ex(tag_name.data(), tag_name.length(), lyrics.data(), lyrics.length());
        return true;
    };

    try {
        service_ptr_t<file_info_filter> updater = file_info_filter::create(update_meta_tag);
        service_ptr_t<metadb_io_v2> meta_io = metadb_io_v2::get();

        meta_io->update_info_async(
            pfc::list_single_ref_t<metadb_handle_ptr>(track),
            updater,
            core_api::get_main_window(),
            metadb_io_v2::op_flag_delay_ui | metadb_io_v2::op_flag_partial_info_aware,
            nullptr
        );

        message << "Successfully queued tag update (" << lyrics.length() << " chars)\n";
        return true;
    }
    catch (const std::exception& e) {
        message << "Error: " << e.what() << "\n";
        return false;
    }
}


// Auto search and save to .lrc file
static void RunAutoSearchSaveFile(metadb_handle_list_cref data, bool show_popup) {
    pfc::string_formatter message;

    if (data.get_count() == 0) {
        message << "No track selected\n";
        if (show_popup) {
            popup_message::g_show(message, "Auto Search & Save");
        } else {
            console::clearBacklog();
            FB2K_console_formatter() << "[Lyrics] " << message;
        }
        return;
    }

    metadb_handle_ptr track = data.get_item(0);
    const metadb_v2_rec_t track_info = get_full_metadata(track);

    auto [lyrics, source_name] = auto_search_get_best_lyrics(track_info, track, message);

    if (lyrics.empty()) {
        message << "No lyrics found from any source.\n";
    } else {
        message << "Best match from: " << source_name.c_str() << " (" << lyrics.length() << " chars)\n\n";

        // Don't overwrite if lyrics came from cache (file or tag)
        bool is_cached = source_name.find("(cached)") != std::string::npos;
        if (is_cached) {
            message << "Lyrics already cached, skipping save.\n";
        } else if (save_lyrics_to_file(track, lyrics, message)) {
            message << "\n--- Lyrics Preview ---\n";
        }
        message << lyrics.c_str();
    }

    if (show_popup) {
        popup_message::g_show(message, "Auto Search & Save to File");
    } else {
        FB2K_console_formatter() << "[Lyrics] " << message;
    }
}


// Auto search and save to metadata tag
static void RunAutoSearchSaveTag(metadb_handle_list_cref data) {
    pfc::string_formatter message;

    if (data.get_count() == 0) {
        message << "No track selected\n";
        popup_message::g_show(message, "Auto Search & Save");
        return;
    }

    metadb_handle_ptr track = data.get_item(0);
    const metadb_v2_rec_t track_info = get_full_metadata(track);

    auto [lyrics, source_name] = auto_search_get_best_lyrics(track_info, track, message);

    if (lyrics.empty()) {
        message << "No lyrics found from any source.\n";
    } else {
        message << "Best match from: " << source_name.c_str() << " (" << lyrics.length() << " chars)\n\n";

        if (save_lyrics_to_tag(track, lyrics, message)) {
            message << "\n--- Lyrics Preview (first 500 chars) ---\n";
            message << lyrics.substr(0, 500).c_str();
            if (lyrics.length() > 500) {
                message << "\n... [truncated]";
            }
        }
    }

    popup_message::g_show(message, "Auto Search & Save to Tag");
}


metadb_v2_rec_t get_full_metadata(metadb_handle_ptr track)
{
    // This is effectively a duplicate of `metadb_handle_ptr::query_v2_()` except that
    // we need to call get_*full*_info_ref(), not just get_browse_info_ref() so that we
    // always have data for non-standard tags like lyrics when running in fb2k pre-v2.
    // This function can be removed if we migrate to targetting FB2K SDK version 81 or higher.
    
    metadb_handle_v2::ptr track_v2;
    if(track->cast(track_v2))
    {
        return track_v2->query_v2();
    }
    
    metadb_v2_rec_t result = {};
    try
    {
        result.info = track->get_full_info_ref(fb2k::mainAborter());
    }
    catch(pfc::exception ex)
    {
        //        LOG_INFO("Failed to retrieve metadata for track due to IO error: %s", ex.what());
    }
    catch(...)
    {
        //        LOG_INFO("Failed to retrieve metadata for track due to an unknown error");
    }
    return result;
}



static void RunWack(metadb_handle_list_cref data) {
    pfc::string_formatter message;
    
    message << "alu u.\n";
    if (data.get_count() > 0) {
        message << "Parameters:\n";
        for(t_size walk = 0; walk < data.get_count(); ++walk) {
            message << data[walk] << "\n";
        }
    }
    metadb_handle_ptr track = data.get_item(0);
    const metadb_v2_rec_t track_info = get_full_metadata(track);
    azlyrics_search(track_info, message);
    
    popup_message::g_show(message, "yeet");
}

// Playback callback to display cached lyrics when a new track starts
class lyrics_playback_callback : public play_callback_static {
public:
    unsigned get_flags() override {
        return flag_on_playback_new_track;
    }

    void on_playback_starting(play_control::t_track_command p_command, bool p_paused) override {
        FB2K_console_formatter() << "[Lyrics] e";
    }
    void on_playback_stop(play_control::t_stop_reason p_reason) override {}
    void on_playback_seek(double p_time) override {}
    void on_playback_pause(bool p_state) override {}
    void on_playback_edited(metadb_handle_ptr p_track) override {}
    void on_playback_dynamic_info(const file_info& p_info) override {}
    void on_playback_dynamic_info_track(const file_info& p_info) override {}
    void on_playback_time(double p_time) override {}
    void on_volume_change(float p_new_val) override {}

    void on_playback_new_track(metadb_handle_ptr p_track) override {
        const metadb_v2_rec_t track_info = get_full_metadata(p_track);
        std::string artist = track_metadata(track_info, "artist");
        std::string title = track_metadata(track_info, "title");

        // Check for lyrics in metadata tags first, then files
        std::string lyrics = get_cached_lyrics_from_tag(track_info);
        if (lyrics.empty()) {
            lyrics = get_cached_lyrics_from_file(p_track);
        }

        if (!lyrics.empty()) {
            console::clearBacklog();
            FB2K_console_formatter() << "[Lyrics] " << artist.c_str() << " - " << title.c_str() << "\n\n" << lyrics.c_str();
        }
    }
};

FB2K_SERVICE_FACTORY(lyrics_playback_callback);
