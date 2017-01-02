
#include "stdafx.h"
#include "flatkrabsetw.h"
#include <krabs.hpp>

// Exported Functions
FLATKRABSETW_API krabs_user_trace *krabs_create_user_trace(
    krabs_status_ctx *status,
    const wchar_t *name)
{
    krabs::user_trace *trace;
    try
    {
        trace = new krabs::user_trace(name);
    }
    catch (std::exception& ex)
    {
        strcpy_s(status->msg, ARRAYSIZE(status->msg), ex.what());
        status->status = krabs_error_unknown_error;
        return nullptr;
    }

    return (krabs_user_trace*)trace;
}

FLATKRABSETW_API krabs_user_provider *krabs_create_user_provider(
    krabs_status_ctx *status,
    krabs_user_trace *trace,
    const wchar_t *provider_name,
    ULONGLONG any_flags,
    ULONGLONG all_flags)
{
    krabs::provider<> *provider;

    try
    {
        provider = new krabs::provider<>(provider_name);
        provider->any(any_flags);
        provider->all(all_flags);
    }
    catch (std::exception& ex)
    {
        strcpy_s(status->msg, ARRAYSIZE(status->msg), ex.what());
        status->status = krabs_error_unknown_error;
        return nullptr;
    }

    return (krabs_user_provider*)provider;
}

FLATKRABSETW_API void krabs_enable_user_provider(
    krabs_status_ctx *status,
    krabs_user_trace *trace,
    krabs_user_provider *provider)
{
    try
    {
        krabs::user_trace* unwrapped_trace = (krabs::user_trace*)trace;
        krabs::provider<>* unwrapped_provider = (krabs::provider<>*)provider;
        unwrapped_trace->enable(*unwrapped_provider);
    }
    catch (std::exception& ex)
    {
        strcpy_s(status->msg, ARRAYSIZE(status->msg), ex.what());
        status->status = krabs_error_unknown_error;
    }
}

FLATKRABSETW_API krabs_filter *krabs_create_filter(krabs_status_ctx *status)
{
    krabs::event_filter* filter;
    try
    {
        filter = new krabs::event_filter(krabs::predicates::any_event);
    }
    catch (std::exception& ex)
    {
        strcpy_s(status->msg, ARRAYSIZE(status->msg), ex.what());
        status->status = krabs_error_unknown_error;
        return nullptr;
    }

    return (krabs_filter*)filter;
}

FLATKRABSETW_API void krabs_add_event_callback_to_provider(
    krabs_status_ctx *status,
    krabs_user_provider *provider,
    krabs_callback callback)
{
    try
    {
        krabs::provider<> *unwrapped_provider = (krabs::provider<>*)provider;
        unwrapped_provider->add_on_event_callback(callback);
    }
    catch (std::exception& ex)
    {
        strcpy_s(status->msg, ARRAYSIZE(status->msg), ex.what());
        status->status = krabs_error_unknown_error;
    }
}

FLATKRABSETW_API void krabs_start_trace(
    krabs_status_ctx *status,
    krabs_user_trace *trace)
{
    try
    {
        krabs::user_trace* unwrapped_trace = (krabs::user_trace*)trace;
        unwrapped_trace->start();
    }
    catch (std::exception& ex)
    {
        strcpy_s(status->msg, ARRAYSIZE(status->msg), ex.what());
        status->status = krabs_error_unknown_error;
    }
}