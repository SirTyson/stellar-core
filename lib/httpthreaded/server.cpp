//
// server.cpp
// ~~~~~~~~~~
//
// Copyright (c) 2003-2024 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "server.hpp"
#include <signal.h>
#include <sstream>
#include <thread>
#include <utility>

namespace httpThreaded
{
namespace server
{

server::server(const std::string& address, unsigned short port, int maxClient,
               std::size_t threadPoolSize)
    : thread_pool_size_(threadPoolSize)
    , signals_(io_context_)
    , acceptor_(io_context_)
{
    // Register to handle the signals that indicate when the server should exit.
    // It is safe to register for the same signal multiple times in a program,
    // provided all registration for the specified signal is made through Asio.
    signals_.add(SIGINT);
    signals_.add(SIGTERM);
#if defined(SIGQUIT)
    signals_.add(SIGQUIT);
#endif // defined(SIGQUIT)

    asio::ip::tcp::endpoint endpoint(asio::ip::address::from_string(address),
                                     port);
    // Open the acceptor with the option to reuse the address (i.e.
    // SO_REUSEADDR).
    acceptor_.open(endpoint.protocol());
    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.bind(endpoint);
    acceptor_.listen(maxClient);
    do_accept();
}

void
server::start()
{
    event_thread_ = std::make_unique<std::thread>([this] {
        // Create a pool of threads to run the io_context.
        std::vector<std::thread> threads;
        for (std::size_t i = 0; i < thread_pool_size_; ++i)
        {
            threads.emplace_back([this] { io_context_.run(); });
        }

        // Wait for all threads in the pool to exit.
        for (std::size_t i = 0; i < threads.size(); ++i)
        {
            threads[i].join();
        }
    });
}

void
server::add404(routeHandler callback)
{
    addRoute("404", callback);
}

void
server::addRoute(const std::string& routeName, routeHandler callback)
{
    mRoutes[routeName] = callback;
}

void
server::do_accept()
{
    // The newly accepted socket is put into its own strand to ensure that all
    // completion handlers associated with the connection do not run
    // concurrently.
    acceptor_.async_accept(
        asio::make_strand(io_context_),
        [this](std::error_code ec, asio::ip::tcp::socket socket) {
            // Check whether the server was stopped by a signal before this
            // completion handler had a chance to run.
            if (!acceptor_.is_open())
            {
                return;
            }

            if (!ec)
            {
                std::make_shared<connection>(std::move(socket), *this)->start();
            }

            do_accept();
        });
}

server::~server()
{
    io_context_.stop();
    if (event_thread_)
    {
        event_thread_->join();
    }
}

void
server::handle_request(const request& req, reply& rep)
{
    // Decode url to path.
    std::string request_path;
    if (!url_decode(req.uri, request_path))
    {
        rep = reply::stock_reply(reply::bad_request);
        return;
    }

    if (request_path.size() && request_path[0] == '/')
        request_path = request_path.substr(1);

    std::string command;
    std::string params;
    auto pos = request_path.find('?');
    if (pos == std::string::npos)
        command = request_path;
    else
    {
        command = request_path.substr(0, pos);
        params = request_path.substr(pos);
    }

    auto it = mRoutes.find(command);
    if (it != mRoutes.end())
    {
        it->second(params, rep.content);

        rep.status = reply::ok;
        rep.headers.resize(2);
        rep.headers[0].name = "Content-Length";
        rep.headers[0].value = std::to_string(rep.content.size());
        rep.headers[1].name = "Content-Type";
        rep.headers[1].value = "application/json";
    }
    else
    {
        it = mRoutes.find("404");
        if (it != mRoutes.end())
        {
            it->second(params, rep.content);

            rep.status = reply::not_found;
            rep.headers.resize(2);
            rep.headers[0].name = "Content-Length";
            rep.headers[0].value = std::to_string(rep.content.size());
            rep.headers[1].name = "Content-Type";
            rep.headers[1].value = "text/html";
        }
        else
        {
            rep = reply::stock_reply(reply::not_found);
            return;
        }
    }
}

bool
server::url_decode(const std::string& in, std::string& out)
{
    out.clear();
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i)
    {
        if (in[i] == '%')
        {
            if (i + 3 <= in.size())
            {
                int value = 0;
                std::istringstream is(in.substr(i + 1, 2));
                if (is >> std::hex >> value)
                {
                    out += static_cast<char>(value);
                    i += 2;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }
        else if (in[i] == '+')
        {
            out += ' ';
        }
        else
        {
            out += in[i];
        }
    }
    return true;
}

void
server::parseParams(const std::string& params,
                    std::map<std::string, std::string>& retMap)
{
    bool buildingName = true;
    std::string name, value;
    for (auto c : params)
    {
        if (c == '?')
        {
        }
        else if (c == '=')
        {
            buildingName = false;
        }
        else if (c == '&')
        {
            buildingName = true;
            retMap[name] = value;
            name = "";
            value = "";
        }
        else
        {
            if (buildingName)
                name += c;
            else
                value += c;
        }
    }
    if (name.size() && value.size())
    {
        retMap[name] = value;
    }
}

} // namespace server
} // namespace httpThreaded