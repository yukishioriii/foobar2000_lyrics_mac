#include <tidy.h>
#include <tidybuffio.h>
#include <stdio.h>
#include <errno.h>

#include <string>
#include <iostream>
#include <fstream>
#include <iterator>

using namespace std;

int main(int argc, char **argv)
{
    using namespace std;
    ifstream f("/Users/ando/work/baking/foobarSDK/foobar2000/foo_sample/log/myfile.html");

    // Check if the file is
    // successfully opened
    if (!f.is_open()) {
        cerr << "Error opening the file!";
        return 1;
    }
    string s;
    string str;

    // Read each line of the file, store
    // it in string s and print it to the
    // standard output stream
    while (getline(f, s)) {
        str.append(s);
    }
        

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
        rc = tidyParseString(tdoc, str.c_str()); // Parse the input
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
            printf("\nDiagnostics:\n\n%s", errbuf.bp);
        printf("\nAnd here is the result:\n\n%s", output.bp);
    }
    else
        printf("A severe error (%d) occurred.\n", rc);

    tidyBufFree(&output);
    tidyBufFree(&errbuf);
    tidyRelease(tdoc);
    return rc;
}
