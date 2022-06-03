#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct ngx_http_test_ctx
{
    ngx_http_request_t *r;
    ngx_chain_t input;
    ngx_chain_t *output;
    ngx_chain_t *output_end; // last link in chain
} ngx_http_test_ctx_t;

typedef struct ngx_http_test_loc_conf
{
    ngx_str_t test;
} ngx_http_test_loc_conf_t;

typedef struct ngx_http_test_main_conf
{
    ngx_log_t *log;
    ngx_str_t test_conf;
    struct test_location_t
    {
        ngx_http_test_loc_conf_t *loc;
        struct test_location_t *prev;
    } *locations; // references in order to prepare on init_process
} ngx_http_test_main_conf_t;

static void* ngx_http_test_create_main_conf(ngx_conf_t *cf);

static char* ngx_http_test_init_main_conf(ngx_conf_t *cf, void *main_conf_ptr);

static void* ngx_http_test_create_loc_conf(ngx_conf_t *cf);

static char* ngx_http_test_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char* ngx_http_test_post_test_test(ngx_conf_t *cf, void *post, void *field);

static ngx_int_t ngx_http_test_init_process(ngx_cycle_t *cycle);

static void ngx_http_test_exit_process(ngx_cycle_t *cycle);

static ngx_int_t ngx_http_test_request_handler(ngx_http_request_t *r);

static void ngx_http_test_request_data_handler(ngx_http_request_t *r);

static ngx_int_t execute_request(ngx_http_test_ctx_t *test_request);

static ngx_int_t send_response(ngx_http_test_ctx_t *test_request);

static ngx_table_elt_t* search_headers_in(const ngx_http_request_t *r, const char *name, size_t len);

ngx_conf_post_t ngx_http_test_test_post = { ngx_http_test_post_test_test };

static ngx_command_t
ngx_http_test_commands[] =
{
    {   // directive to set 'test' for location configuration
        ngx_string("test"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_test_loc_conf_t, test),
        &ngx_http_test_test_post // post handler
    },
    {   // directive to set 'test_conf' for main configuration
        ngx_string("test_conf"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_test_main_conf_t, test_conf),
        NULL // post handler
    },
    ngx_null_command
};

static ngx_http_module_t
ngx_http_test_module_ctx =
{
    NULL, // preconfiguration
    NULL, // postconfiguration
    ngx_http_test_create_main_conf, // create main configuration
    ngx_http_test_init_main_conf, // init main configuration
    NULL, // create server configuration
    NULL, // merge server configuration
    ngx_http_test_create_loc_conf, // allocates and initializes location-scope struct
    ngx_http_test_merge_loc_conf   // sets location-scope struct values from outer scope if left unset in location scope
};

ngx_module_t
ngx_http_test_module =
{
    NGX_MODULE_V1,
    &ngx_http_test_module_ctx,  // module callbacks
    ngx_http_test_commands,     // module configuration callbacks
    NGX_HTTP_MODULE,           // module type is HTTP
    NULL,        // init_master
    NULL,        // init_module
    ngx_http_test_init_process, // init_process
    NULL,        // init_thread
    NULL,        // exit_thread
    ngx_http_test_exit_process, // exit_process
    NULL,        // exit_master
    NGX_MODULE_V1_PADDING
};



static void*
ngx_http_test_create_main_conf(ngx_conf_t *cf)
{
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "plugin-test: [PID=%d] %s", ngx_pid, __FUNCTION__);
    ngx_http_test_main_conf_t *main_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_test_main_conf_t));
    // if (main_conf != NULL)
    // {
    // }
    return main_conf;
}
static char*
ngx_http_test_init_main_conf(ngx_conf_t *cf, void *main_conf_ptr)
{
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,"plugin-test: [PID=%d] %s", ngx_pid, __FUNCTION__);
    // ngx_http_test_main_conf_t *main_conf = main_conf_ptr;
    // if (main_conf->config == NGX_CONF_UNSET_PTR)
    // {
    // }
    return NGX_CONF_OK;
}

static void*
ngx_http_test_create_loc_conf(ngx_conf_t *cf)
{
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "plugin-test: [PID=%d] %s", ngx_pid, __FUNCTION__);
    ngx_http_test_loc_conf_t *loc_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_test_loc_conf_t));
    if (loc_conf != NULL)
    {
    }
    return loc_conf;
}

static char*
ngx_http_test_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "plugin-test: [PID=%d] %s", ngx_pid, __FUNCTION__);
    ngx_http_test_loc_conf_t *prev = parent;
    ngx_http_test_loc_conf_t *loc_conf = child;
    ngx_conf_merge_str_value(loc_conf->test, prev->test, /*default*/ "");
    return NGX_CONF_OK;
}

static char*
ngx_http_test_post_test_test(ngx_conf_t *cf, void *post, void *data)
{
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "plugin-test: [PID=%d] %s", ngx_pid, __FUNCTION__);


    // setting "test" also enables HTTP handler for location
    ngx_http_core_loc_conf_t *http_core_loc_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    http_core_loc_conf->handler = ngx_http_test_request_handler; // sets HTTP request handler

    // push_front locations because they are prepared in init_process
    ngx_http_test_main_conf_t *main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_test_module);
    ngx_http_test_loc_conf_t *loc_conf = (ngx_http_test_loc_conf_t*)((uint8_t)data - offsetof(ngx_http_test_loc_conf_t, test));
    ngx_str_t *test = data;
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "plugin-test: [PID=%d] %s test=%V", ngx_pid, __FUNCTION__, test);
    // ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "plugin-test: [PID=%d] %s test=%V", ngx_pid, __FUNCTION__, &loc_conf->test);

    // linked-list: 1 <- 2 <- 3
    struct test_location_t *l = ngx_palloc(cf->pool, sizeof(struct test_location_t));
    l->loc = loc_conf;
    l->prev = main_conf->locations;
    main_conf->locations = l;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_test_init_process(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "plugin-test: [PID=%d] %s pid=%d", ngx_pid, __FUNCTION__, ngx_pid);

    ngx_http_test_main_conf_t *main_conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_test_module);

    if (!main_conf)
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "plugin-test: [PID=%d] !main_conf", ngx_pid);
        return NGX_ERROR;
    }

    main_conf->log = cycle->log;

    struct test_location_t *location = main_conf->locations;
    while (location)
    {
        // ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "plugin-test: [PID=%d] preparing test %V", ngx_pid, location->loc->test);
        // ngx_http_test_loc_conf_t *loc_conf = location->loc;
        location = location->prev;
    }

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "plugin-test: [PID=%d] test_conf = %V", ngx_pid, &main_conf->test_conf);
    return NGX_OK;
}

static void
ngx_http_test_exit_process(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "plugin-test: [PID=%d] %s", ngx_pid, __FUNCTION__);
    // ngx_http_test_main_conf_t *main_conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_test_module);
    // struct test_location_t *location = main_conf->locations;
    // while (location)
    // {
    //     location = location->prev;
    // }
}


static ngx_int_t
ngx_http_test_request_handler(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "plugin-test: [PID=%d] %s pid=%d", ngx_pid, __FUNCTION__, ngx_pid);

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_POST)))
    {
        return NGX_HTTP_NOT_ALLOWED;
    }
    ngx_http_test_ctx_t *test_request = ngx_pcalloc(r->pool, sizeof(ngx_http_test_ctx_t)); // NOTE: zero-initialized
    if (test_request == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_set_ctx(r, test_request, ngx_http_test_module); // makes context retrievable from r with ngx_http_get_module_ctx(r, ngx_http_test_module)
    test_request->r = r;

    if ((r->method & NGX_HTTP_GET) && ngx_http_discard_request_body(r) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_int_t ret = ngx_http_read_client_request_body(r, ngx_http_test_request_data_handler); // delegates to body handler callback
    if (ret >= NGX_HTTP_SPECIAL_RESPONSE)
    {
        return ret;
    }
    return NGX_DONE; // doesn't destroy request until ngx_http_finalize_request is called
}


static void
ngx_http_test_request_data_handler(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "plugin-test: [PID=%d] %s", ngx_pid, __FUNCTION__);

    ngx_http_test_ctx_t *test_request = ngx_http_get_module_ctx(r, ngx_http_test_module);

    off_t buffer_size = 0;
    for (ngx_chain_t *cl = r->request_body->bufs; cl; cl = cl->next)
    {
        buffer_size += ngx_buf_size(cl->buf);
    }

    if (buffer_size)
    {
        // copy incoming buffer into contiguous input buffer
        if (test_request->input.buf == NULL)
        {
            test_request->input.buf = ngx_create_temp_buf(r->pool, buffer_size);
        }
        else
        {
            off_t capacity = test_request->input.buf->end - test_request->input.buf->start;
            off_t used = test_request->input.buf->last - test_request->input.buf->pos;
            if (buffer_size > capacity - used) // if incoming buffers' data can't fit in current storage
            {
                // realloc storage to also fit incoming buffers
                ngx_buf_t *buf = ngx_create_temp_buf(r->pool, buffer_size + capacity);
                buf->last = ngx_cpymem(buf->pos, test_request->input.buf->pos, used);
                test_request->input.buf = buf;
            }
        }

        for (ngx_chain_t *cl = r->request_body->bufs; cl; cl = cl->next) // copy all incoming buffers to storage
        {
            // ngx_str_t str = {ngx_buf_size(cl->buf), cl->buf->pos};
            // ngx_log_error(NGX_LOG_INFO, test_request->r->connection->log, 0, "plugin-test: [PID=%d] buffer = '[%V]'", ngx_pid, &str);

            ngx_buf_t *buf = test_request->input.buf;

            if (cl->buf->in_file || cl->buf->temp_file) // if buffered in file, then read entire file into a buffer
            {
                ngx_log_error(NGX_LOG_INFO, test_request->r->connection->log, 0, "plugin-test: [PID=%d] buffer in file", ngx_pid);
                ssize_t bytes_read = ngx_read_file(cl->buf->file, buf->pos, buffer_size, cl->buf->file_pos);
                if (bytes_read != (ssize_t)buffer_size)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "plugin-test: [PID=%d] error reading tempfile; ret=%zu", ngx_pid, bytes_read);
                    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }
                buf->last = buf->pos + bytes_read;
            }
            else
            {
                buf->last = ngx_cpymem(buf->pos, cl->buf->pos, ngx_buf_size(cl->buf));
            }
            buf->last_buf = cl->buf->last_buf;
        }
    }

    // begin request handling when all input has been received (i.e. if there was no input or 'last buffer' flag is set)
    if (!test_request->input.buf || (test_request->input.buf->last_buf))
    {
        ngx_int_t ret = execute_request(test_request);
        if (ret != NGX_OK)
        {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        else
        {
            ngx_http_finalize_request(r, send_response(test_request));
        }
        // to instead finalize later, something needs to trigger a callback
    }
    else
    {   // chunked input?
        ngx_log_error(NGX_LOG_INFO, test_request->r->connection->log, 0, "plugin-test: [PID=%d] chunk", ngx_pid);
    }
}


static ngx_int_t
execute_request(ngx_http_test_ctx_t *test_request)
{
    ngx_log_error(NGX_LOG_INFO, test_request->r->connection->log, 0, "plugin-test: [PID=%d] %s", ngx_pid, __FUNCTION__);

    ngx_http_test_loc_conf_t *loc_conf = ngx_http_get_module_loc_conf(test_request->r, ngx_http_test_module);
    // ngx_http_test_main_conf_t *main_conf = ngx_http_get_module_main_conf(test_request->r, ngx_http_test_module);

    ngx_str_t *test = &loc_conf->test;
    ngx_log_error(NGX_LOG_INFO, test_request->r->connection->log, 0, "plugin-test: [PID=%d] %s test=%V", ngx_pid, __FUNCTION__, test);

    // there may not be any output, but prepare anyway
    off_t buffer_capacity = 4096; // each
    ngx_buf_t *buf = ngx_create_temp_buf(test_request->r->pool, buffer_capacity);
    buf->memory = 1;
    ngx_chain_t *chain = ngx_alloc_chain_link(test_request->r->pool);
    chain->buf = buf;
    chain->next = NULL;
    test_request->output = test_request->output_end = chain;

    if (test_request->input.buf) // if there is request data
    {
        const char *request_body = (const char*)test_request->input.buf->pos;
        const char *end = (const char*)test_request->input.buf->last;
        size_t len = end - request_body;
        ngx_str_t str={len, (unsigned char*)request_body};
        ngx_log_error(NGX_LOG_INFO, test_request->r->connection->log, 0, "plugin-test: [PID=%d] request body = '%V'", ngx_pid, &str);
    }

    // struct header { ngx_str_t name, value; } headers[] =
    // {
    //     {ngx_string("HEADERTEST"), ngx_string("")},
    //     {ngx_string("HEADERTEST2") , ngx_string("")}
    // };
    // for (const struct header *h = &headers[0]; h != &headers[sizeof headers / sizeof *headers]; h += 1)
    // {
    //     ngx_table_elt_t *header_element = search_headers_in(test_request->r, (const char*)h->name.data, h->name.len);
    //     if (header_element != NULL)
    //     {
    //         h->value.data = header_element->value.data;
    //         h->value.len = header_element->value.len;
    //     }
    //     ngx_log_error(NGX_LOG_INFO, test_request->r->connection->log, 0, "plugin-test: [PID=%d] header %V='%V'", ngx_pid, &h->name, &h->value);
    // }

    {
        const ngx_list_part_t *part = &test_request->r->headers_in.headers.part;
        ngx_table_elt_t *h = part->elts;
        for (unsigned i = 0; /* void */ ; i += 1)
        {
            if (i >= part->nelts)
            {
                if (part->next == NULL)
                {
                    break; 
                }
                part = part->next;
                h = part->elts;
                i = 0;
            }
            ngx_str_t *header_key = &h[i].key;
            ngx_str_t *header_value = &h[i].value;
            ngx_log_error(NGX_LOG_INFO, test_request->r->connection->log, 0, "plugin-test: [PID=%d] header %V='%V'", ngx_pid, header_key, header_value);
        }
    }

    // size_t data_length = 0;
    // const unsigned char *data_value = (const unsigned char*)"HELLO";
    // data_length = sizeof "HELLO"-1;
    const unsigned char *data_value = test->data;
    size_t data_length = test->len;

    ngx_log_error(NGX_LOG_INFO, test_request->r->connection->log, 0, "plugin-test: [PID=%d] data_value = '%s'", ngx_pid, data_value);

    if (buf->last + data_length >= buf->end)
    {   // create and chain another buffer if previous can't fit the data
        if ((off_t)data_length > buffer_capacity)
        {
            buffer_capacity = data_length;
        }
        buf = ngx_create_temp_buf(test_request->r->pool, buffer_capacity);
        buf->memory = 1;
        if (test_request->output_end->buf->last == test_request->output_end->buf->pos)
        {   // if previous buffer is empty, overwrite it with the new one.
            test_request->output_end->buf = buf;
        }
        else // append new buffer in chain
        {
            chain = ngx_alloc_chain_link(test_request->r->pool);
            chain->buf = buf;
            chain->next = NULL;
            test_request->output_end->next = chain;
            test_request->output_end = chain;
        }
    }

    buf->last = ngx_cpymem(buf->last, data_value, data_length);

    test_request->r->headers_out.status = NGX_HTTP_OK;
    return NGX_OK;
}

static ngx_int_t
send_response(ngx_http_test_ctx_t *test_request)
{
    ngx_http_request_t *r = test_request->r;
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "plugin-test: [PID=%d] %s", ngx_pid, __FUNCTION__);

    if (test_request->output)
    {
        ngx_str_t str = {ngx_buf_size(test_request->output->buf), test_request->output->buf->pos};
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "plugin-test: [PID=%d] output buffer[0] = '%V'", ngx_pid, &str);
    }
    else
    {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "plugin-test: [PID=%d] no output", ngx_pid);
    }

    off_t content_length = 0;
    for (ngx_chain_t *cl = test_request->output; cl; cl = cl->next)
    {
        content_length += ngx_buf_size(cl->buf);
        if (cl->next == NULL)
        {
            cl->buf->last_in_chain = 1;
            cl->buf->last_buf = 1;
        }
    }
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "plugin-test: [PID=%d] content_length=%O", ngx_pid, content_length);

    if (r->headers_out.status == 0)
    {
        r->headers_out.status = NGX_HTTP_OK;
    }
    r->headers_out.content_length_n = content_length;
    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    if (content_length == 0)
    {
        r->header_only = 1;
    }

    if (ngx_http_send_header(r) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "plugin-test: [PID=%d] ngx_http_send_header(r) != NGX_OK", ngx_pid);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (content_length != 0)
    {
        if (ngx_http_output_filter(r, test_request->output) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "plugin-test: [PID=%d] ngx_http_output_filter() != NGX_OK", ngx_pid);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return r->headers_out.status;
}


static ngx_table_elt_t*
search_headers_in(const ngx_http_request_t *r, const char *name, size_t len)
{
   const ngx_list_part_t *part = &r->headers_in.headers.part;
   ngx_table_elt_t *h = part->elts;

   for (unsigned i = 0; /* void */ ; i += 1)
   {
      if (i >= part->nelts)
      {
         if (part->next == NULL)
         {
            break; 
         }
         part = part->next;
         h = part->elts;
         i = 0;
      }
      if (len != h[i].key.len || ngx_strcasecmp((u_char*)name, h[i].key.data) != 0)
      {
         continue;
      }

      return &h[i];
   }
   return NULL;
}
