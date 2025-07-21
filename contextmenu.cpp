#include "stdafx.h"
#include <curl/curl.h>
#include <string>
#include <pugixml.hpp>

#include <tidy.h>
#include <tidybuffio.h>
#include <stdio.h>

#include <fstream>

// Identifier of our context menu group. Substitute with your own when reusing code.
static const GUID guid_mygroup = { 0x572de7f4, 0xcbdf, 0x479a, { 0x97, 0x26, 0xa, 0xb0, 0x97, 0x47, 0x69, 0xe3 } };


// Switch to contextmenu_group_factory to embed your commands in the root menu but separated from other commands.

//static contextmenu_group_factory g_mygroup(guid_mygroup, contextmenu_groups::root, 0);
static contextmenu_group_popup_factory g_mygroup(guid_mygroup, contextmenu_groups::root, "Lyrics find", 0);

static void RunTestCommand(metadb_handle_list_cref data);

static void RunWack(metadb_handle_list_cref data);

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
        cmd_test1 = 0,
        wack,
        cmd_total
    };
    GUID get_parent() {return guid_mygroup;}
    unsigned get_num_items() {return cmd_total;}
    void get_item_name(unsigned p_index,pfc::string_base & p_out) {
        switch(p_index) {
            case cmd_test1: p_out = "ignored"; break;
            case wack: p_out = "Lyrics pls"; break;
            default: uBugCheck(); // should never happen unless somebody called us with invalid parameters - bail
        }
    }
    void context_command(unsigned p_index,metadb_handle_list_cref p_data,const GUID& p_caller) {
        switch(p_index) {
            case cmd_test1:
                RunTestCommand(p_data);
                break;
            case wack:
                RunWack(p_data);
                break;
            default:
                uBugCheck();
        }
    }
    // Overriding this is not mandatory. We're overriding it just to demonstrate stuff that you can do such as context-sensitive menu item labels.
    bool context_get_display(unsigned p_index,metadb_handle_list_cref p_data,pfc::string_base & p_out,unsigned & p_displayflags,const GUID & p_caller) {
        switch(p_index) {
            case cmd_test1:
                if (!super_t::context_get_display(p_index, p_data, p_out, p_displayflags, p_caller)) return false;
                // Example context sensitive label: append the count of selected items to the label.
                p_out << " : " << p_data.get_count() << " item";
                if (p_data.get_count() != 1) p_out << "s";
                p_out << " selected";
                return true;
            default:
                return super_t::context_get_display(p_index, p_data, p_out, p_displayflags, p_caller);
        }
    }
    GUID get_item_guid(unsigned p_index) {
        // These GUIDs identify our context menu items. Substitute with your own GUIDs when reusing code.
        static const GUID guid_test1 = { 0x4021c80d, 0x9340, 0x423b, { 0xa3, 0xe2, 0x8e, 0x1e, 0xda, 0x87, 0x13, 0x7f } };
        static const GUID guid_wack = { 0x4021c79d, 0x9340, 0x423b, { 0xa3, 0xe2, 0x8e, 0x1e, 0xda, 0x87, 0x13, 0x7f } };
        
        switch(p_index) {
            case cmd_test1: return guid_test1;
            case wack: return guid_wack;
            default: uBugCheck(); // should never happen unless somebody called us with invalid parameters - bail
        }
        
    }
    bool get_item_description(unsigned p_index,pfc::string_base & p_out) {
        switch(p_index) {
            case cmd_test1:
                p_out = "This is a sample command.";
                return true;
            case wack:
                p_out = "guh.";
                return true;
            default:
                uBugCheck(); // should never happen unless somebody called us with invalid parameters - bail
        }
    }
};

static contextmenu_item_factory_t<myitem> g_myitem_factory;


static void RunTestCommand(metadb_handle_list_cref data) {
    pfc::string_formatter message;
    message << "This is a test command.\n";
    if (data.get_count() > 0) {
        message << "Parameters:\n";
        for(t_size walk = 0; walk < data.get_count(); ++walk) {
            message << data[walk] << "\n";
        }
    }
    popup_message::g_show(message, "Blah");
}



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

static void azlyrics_search(pfc::string_formatter& message) {
    
    CURL *curl;
    CURLcode res;
    std::string readBuffer;
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://www.azlyrics.com/lyrics/mileycyrus/wtfdoiknow.html");
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
        message << lyric_text.c_str() << "\n";
        //        console::print(lyric_text.c_str());
        
        //        message << readBuffer.c_str() << "\n";
    }
}



static void RunWack(metadb_handle_list_cref data) {
    pfc::string_formatter message;
    
    message << "Feck u.\n";
    if (data.get_count() > 0) {
        message << "Parameters:\n";
        for(t_size walk = 0; walk < data.get_count(); ++walk) {
            message << data[walk] << "\n";
        }
    }
    
    popup_message::g_show(message, "yeet");
}

