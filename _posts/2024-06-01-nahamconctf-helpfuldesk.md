---
layout: post
title: "[nahamconCTF 2024] Helpful Desk"
author: edaigle
---

## Problem Description

> HelpfulDesk is the go-to solution for small and medium businesses who need remote monitoring and management. Last night, HelpfulDesk released a security bulletin urging everyone to patch to the latest patch level. They were scarce on the details, but I bet that can't be good...

This was categorized as a web challenge, although most of my time on it was spent reverse engineering.

Difficulty: easy

## Initial Research

Opening up the URL, we see this is supposed to be a login to a remote access
software. There's a note at the top telling us to download the latest update
for important security fixes. Clicking the note brings us to an "updates" page
with a list of releases we can download. Presumably the current instance is
running the old insecure version, so let's download it and the latest and
find the difference.

## Exploring the codebase

Downloading the two versions and unzipping them, we see this is a .NET server.
Running diff on the folders, we see the only thing that has changed is
HelpfulDesk.dll.

## Decompiling

Let's decompile the old and new versions of the DLL with AvaloniaILSpy.
Renaming the dlls for convenience to HelpfulDesk-old and HelpfulDesk-new,
we can conveniently export the decompiled code to a flat text file by
right-clicking each dll and choosing "Save Code."

Now we can open both files in Emacs and use ediff to find the changes.
After skipping through the filenames and a few uninteresting hashes, we
only find one significant change:

### HelpfulDesk-new.dll

``` c#
  public IActionResult SetupWizard()
  {
      //IL_0018: Unknown result type (might be due to invalid IL or missing references)
      //IL_001d: Unknown result type (might be due to invalid IL or missing references)
      if (File.Exists(_credsFilePath))
      {
          PathString path = ((ControllerBase)this).get_HttpContext().get_Request().get_Path();
          string text = ((PathString)(ref path)).get_Value().TrimEnd('/');
          if (text.Equals("/Setup/SetupWizard", StringComparison.OrdinalIgnoreCase))
          {
              return (IActionResult)(object)((Controller)this).View("Error", (object)new ErrorViewModel
                                                                    {
                                                                        RequestId = "Server already set up.",
                                                                        ExceptionMessage = "Server already set up.",
                                                                        StatusCode = 403
                                                                    });
          }
      }
      return (IActionResult)(object)((Controller)this).View();
  }
```

### HelpfulDesk-old.dll

``` c#
  public IActionResult SetupWizard()
  {
      //IL_0018: Unknown result type (might be due to invalid IL or missing references)
      //IL_001d: Unknown result type (might be due to invalid IL or missing references)
      if (File.Exists(_credsFilePath))
      {
          PathString path = ((ControllerBase)this).get_HttpContext().get_Request().get_Path();
          string value = ((PathString)(ref path)).get_Value();
          if (value.Equals("/Setup/SetupWizard", StringComparison.OrdinalIgnoreCase))
          {
              return (IActionResult)(object)((Controller)this).View("Error", (object)new ErrorViewModel
                                                                    {
                                                                        RequestId = "Server already set up.",
                                                                        ExceptionMessage = "Server already set up.",
                                                                        StatusCode = 403
                                                                    });
          }
      }
      return (IActionResult)(object)((Controller)this).View();
  }
```

## Exploit

I don't know the exact mechanisms here, but at
a high level it seems to be controlling access to the /Setup/SetupWizard
endpoint. If the credential file exists, it denies access to the endpoint.
Presumably the SetupWizard lets us reset credentials, so this ensures only the
admin doing the initial setup can access it.

The difference between the function in the old and new files is that the new one
strips trailing slashes from /Setup/SetupWizard. We can see the security flaw: if
we navigate to the path with the trailing slash, the value.Equals() won't be triggered,
but ASP.NET will ignore the slash and serve us the Setup page.

Giving it a try, this works! I get the setup page and reset the login credentials. I
then login and find the flag on the first connected computer's desktop.
