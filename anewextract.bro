@load /opt/bro/share/bro/base/utils/urls.bro

global ext_map: table[string] of string = {
["application/java-archive"] = "jar",
["application/msword"] = "doc",
["application/vnd.ms-reg"] = "reg",
["application/vnd.ms-regf"] = "reg",
["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = "docx",
["application/x-ms-shortcut"] = "lnk",
["application/x-object"] = "xobj",
["application/x-executable"] = "xexe",
["application/x-sharedlib"] = "xsha",
["application/x-coredump"] = "xcor",
["application/x-dosexec"] = "exe",
["application/x-shockwave-flash"] = "swf",
["application/x-tar"] = "tar",
["application/x-kaspavdb"] = "kasp",
["application/x-kaspavupdate"] = "kasp",
["application/zip"] = "zip",
["text/x-shellscript"] = "SHELL",
} &default ="";

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( ! meta?$mime_type || meta$mime_type !in ext_map )
        return;

    local ext = "";
    local fname = "";
    local urls = decompose_uri(f$http$uri);

    if ( meta?$mime_type )
        ext = ext_map[meta$mime_type];

    if ( f$source == "HTTP" && f?$http && f$http?$uri )
    {
        if ( meta$mime_type == "application/x-dosexec" && f?$info && f$info?$filename ) 
        {
            fname = fmt("/nsm/bro/extracted/%s-%s--%s", f$source, f$id, f$info$filename);
        }
        else 
        {
            fname = fmt("/nsm/bro/extracted/%s-%s-%s", f$source, f$id, urls$file_name);
        }
    }

    else 
    {
        fname = fmt("/nsm/bro/extracted/%s-%s.%s", f$source, f$id, ext);
    }
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
    }
