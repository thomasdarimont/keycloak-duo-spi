<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "title">
        ${msg("loginTitle",realm.name)}
    <#elseif section = "header">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        ${msg("loginTitleHtml",realm.name)}
    <#elseif section = "form">
        <iframe id="duo_iframe" data-host="${apihost}" data-sig-request="${sig_request}" data-post-action="${url.loginAction}">
        </iframe>
        <style>
            #duo_iframe {
                width: 100%;
                min-width: 304px;
                max-width: 620px;
                height: 330px;
                border: none;
            }
        </style>
    </#if>
</@layout.registrationLayout>