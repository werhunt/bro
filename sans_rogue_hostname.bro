@load base/frameworks/notice
@load policy/protocols/smb

export 
{
    redef enum Notice::Type += {
    SMB
};

event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
{

# strip out the first 5 characters of workstation value to be compared to naming convention
local strcheck = sub_bytes(request$workstation, 1, 8);

# value of the comparison of the two strings
local comp_str = strcmp(strcheck, “WIN7PROD”);

# If the comparison of the strings stored in variable comp_str are not the same, generate a notice.
    if (comp_str != 0 )
    {
        NOTICE([$note=SMB, $msg=fmt(“Potential Lateral Movement Activity – Invalid Hostname using Domain Credentials”), $sub=fmt(“%s,%s”,”Suspicious Hostname:”, request$workstation), $conn=c]);
    }
}

}
