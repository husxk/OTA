#pragma once
#include <string>
#include <vector>
#include <memory>
#include "file_wrapper.h"

class file_reader
{
public:
    file_reader() = default;
    ~file_reader() = default;

    bool load_file(const std::string& file_path);
    size_t read_bytes(uint8_t* buffer, size_t max_bytes);

    std::string get_file_path() const
    {
        return file_path;
    }

    size_t get_file_size() const
    {
        return file_size;
    }

    size_t get_bytes_sent() const
    {
        return bytes_sent;
    }

    void add_bytes_sent(size_t bytes)
    {
        bytes_sent += bytes;
    }

    bool is_transfer_complete() const
    {
        return bytes_sent >= file_size;
    }

protected:
    std::string file_path;
    file_wrapper file_handle;
    bool is_loaded = false;
    bool eof_reached = false;
    size_t file_size = 0;
    size_t bytes_sent = 0;

private:
    void handle_fatal_error(const char* operation) const;
};