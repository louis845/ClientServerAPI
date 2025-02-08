import socket
import ssl
import threading
import json
import logging
import traceback
import time
from typing import Optional, Union, Callable, Any

from .server_abstract import AbstractAPIServer
from .http_parse import parse_http_request, HttpRequest
from .http_write import send_http_response
from .login_session import LoginSession
from . import utils

_EXIT_REASON_DEFAULT = "Unset"
class _ThreadFlags:
    """Exit reason for the client handler."""
    address: tuple[str, int]
    exit_reason: str
    stop_flag: bool

    def __init__(self, address: tuple[str, int]) -> None:
        self.exit_reason = _EXIT_REASON_DEFAULT
        self.address = address
        self.stop_flag = False

def handle_client(client_socket: Union[socket.socket, ssl.SSLSocket], addr, serverInst: "ThreadedAPIServer",
                  thread_flags: _ThreadFlags,
                  login_params: dict[str, str]) -> str:
    """Handle an individual client connection."""
    try:
        timeout_count = 0
        socket_valid = True # flag to check if the socket is still valid.
        while socket_valid:
            request: Optional[HttpRequest] = parse_http_request(client_socket, serverInst.max_recv_calls_per_request)
            if request is None: # timeout occurred, but socket is still valid since nothing was received. if timeout is happens between sending some HTTP request, the request will be returned with some error.
                if thread_flags.stop_flag:
                    thread_flags.exit_reason = "Thread for {}:{} flagged to be stopped.".format(addr[0], addr[1])
                    break # stop the loop if the stop flag is set
                else:
                    timeout_count += 1
                    if timeout_count >= 10: # if there are too many timeouts, exit the thread. this means that the client is not sending anything in roughly 10 * timeout seconds.
                        thread_flags.exit_reason = "Thread for {}:{} has too many timeouts.".format(addr[0], addr[1])
                        break
                    continue
            timeout_count = 0 # reset the timeout count

            if request.hasError(): # if there is an error in the request, send a 400 Bad Request response
                error_msg = request.errorMsg()
                send_http_response(client_socket, 400, {"Content-Type": "application/json", "Connection": "Close"}, json.dumps({"error": error_msg}).encode())
                socket_valid = False
                thread_flags.exit_reason = "Error parsing request from {}:{}.\n\n{}".format(addr[0], addr[1], error_msg)
                break
            
            # handle the response using route_request
            needs_close = route_request(client_socket, request, serverInst, thread_flags, login_params)
            if needs_close or request.closing_requested(): # if the request is a closing request, or if the server requests a close, close the socket
                socket_valid = False
                if needs_close:
                    if thread_flags.exit_reason == _EXIT_REASON_DEFAULT: # do not overwrite the reason if it is already set by subrouting functions
                        thread_flags.exit_reason = "Server requested close."
                else:
                    thread_flags.exit_reason = "Client requested close."
    except Exception as e:
        thread_flags.exit_reason = "Unexpected error in client handler. Exception: {}\n\n{}".format(str(e), traceback.format_exc())
    finally:
        # close the client socket
        thread_flags.stop_flag = True
        client_socket.close()

def route_request(client_socket: Union[socket.socket, ssl.SSLSocket],
                  request: HttpRequest,
                  serverInst: "ThreadedAPIServer",
                  thread_flags: _ThreadFlags,
                  login_params: dict[str, str]) -> bool:
    """Route the HTTP request to the appropriate handler."""
    method = request.get_method()
    path = request.get_path()
    body = request.get_body()
    headers = request.get_headers()
    if path == "/login" and method == "POST":
        return handle_login(client_socket, body, serverInst, login_params["level"], login_params["use_tls"])
    elif path == "/logout" and method == "POST":
        return handle_logout(client_socket, headers, serverInst)
    elif path == "/communicate" and method == "POST":
        return handle_communicate(client_socket, headers, body, serverInst, thread_flags)
    else:
        # send http response with 400 Bad Request
        send_http_response(client_socket, 400, {"Content-Type": "application/json", "Connection": "Close"}, json.dumps({"error": "Invalid request."}).encode())
        return True # we close the connection after sending the response

def handle_login(client_socket: Union[socket.socket, ssl.SSLSocket],
                 body: Optional[bytes],
                 serverInst: "ThreadedAPIServer",
                 level: str,
                 use_tls: str) -> bool:
    """Handle the login request. Request close if the login fails, otherwise close it if and only if the client wants it."""
    # see if the body is valid JSON
    if body is None:
        send_http_response(client_socket, 400, {"Content-Type": "application/json", "Connection": "Close"}, json.dumps({"error": "Body required."}).encode())
        return True
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        send_http_response(client_socket, 400, {"Content-Type": "application/json", "Connection": "Close"}, json.dumps({"error": "Invalid JSON."}).encode())
        return True
    if not isinstance(data, dict) or "username" not in data or "password" not in data:
        send_http_response(client_socket, 400, {"Content-Type": "application/json", "Connection": "Close"}, json.dumps({"error": "Username and password required."}).encode())
        return True
    
    # check credentials
    username, password = data["username"], data["password"]
    if ((username not in serverInst.credentials) or
        (serverInst.credentials[username] != password)):
        send_http_response(client_socket, 401, {"Content-Type": "application/json", "Connection": "Close"}, json.dumps({"error": "Invalid credentials."}).encode())
        return True
    
    # login successful. create a session token and store the session.
    session_token = serverInst.generateSessionToken()
    session = LoginSession(username, session_token)
    with serverInst.lock:
        serverInst.sessions.session_dict[session_token] = session
        serverInst.logger.info("Login successful for user {} with session token {}.".format(username, session.get_hashed_session_token()))
    
    # send the session token back to the client by setting it in a cookie
    headers = {"Content-Type": "application/json", "Set-Cookie": utils.format_session_token(session_token, level=level, use_tls=use_tls)}
    send_http_response(client_socket, 200, headers, json.dumps({"message": "Login successful."}).encode())
    return False

def handle_logout(client_socket: Union[socket.socket, ssl.SSLSocket],
                  headers: dict[str, str],
                  serverInst: "ThreadedAPIServer") -> bool:
    """Handle the logout request. We close no matter what."""
    cookies: dict[str, str] = utils.parse_cookies(headers)
    token = cookies.get("sessionToken", None)
    if token is None:
        send_http_response(client_socket, 400, {"Content-Type": "application/json", "Connection": "Close"}, json.dumps({"error": "Session token required."}).encode())
        return True
    with serverInst.lock:
        if token not in serverInst.sessions.session_dict:
            found = False
        else:
            serverInst.sessions.session_dict[token].invalidate() # We can directly get the Session object since its not a subprocess, but a thread.
            found = True
    if found:
        send_http_response(client_socket, 200, {"Content-Type": "application/json", "Connection": "Close"}, json.dumps({"message": "Logout successful."}).encode())
    else:
        send_http_response(client_socket, 401, {"Content-Type": "application/json", "Connection": "Close"}, json.dumps({"error": "Invalid session token."}).encode())
    return True

def handle_communicate(client_socket: Union[socket.socket, ssl.SSLSocket],
                       headers: dict[str, str], body: Optional[bytes],
                       serverInst: "ThreadedAPIServer",
                       thread_flags: _ThreadFlags) -> bool:
    """Handle communication requests. Requires a valid session token. Close if the token is invalid. Otherwise, close if and only if the client requests it."""
    # get session token
    cookies: dict[str, str] = utils.parse_cookies(headers)
    token = cookies.get("sessionToken", None)
    if token is None: # check none
        send_http_response(client_socket, 401, {"Content-Type": "application/json", "Connection": "Close"}, json.dumps({"error": "Invalid session token."}).encode())
        return True # close the connection
    token_valid, username = True, None
    with serverInst.lock:
        if token not in serverInst.sessions.session_dict: # check if token is in sessions, the validity
            token_valid = False
        else:
            username = serverInst.sessions.session_dict[token].get_username()
    if not token_valid: # if not valid, return 401
        send_http_response(client_socket, 401, {"Content-Type": "application/json", "Connection": "Close"}, json.dumps({"error": "Invalid session token."}).encode())
        return True # close the connection

    # try to parse the JSON body
    if body is None:
        send_http_response(client_socket, 400, {"Content-Type": "application/json"}, json.dumps({"error": "Body required."}).encode())
        return False # close only if the client requests it
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        send_http_response(client_socket, 400, {"Content-Type": "application/json"}, json.dumps({"error": "Invalid JSON."}).encode())
        return False # close only if the client requests it
    
    # handle the request
    try:
        force_close, response_json = serverInst.request_callback(username, token, data)
    except Exception as e:
        send_http_response(client_socket, 500, {"Content-Type": "application/json", "Connection": "Close"}, json.dumps({"error": "Internal server error."}).encode())
        err_msg = "\n".join(traceback.format_exception(e))
        thread_flags.exit_reason = "Error in request callback. Stack trace:\n\n{}".format(err_msg)
        serverInst.logger.info("Internal error inside request callback. Stack trace for downstream debugging:")
        serverInst.logger.info(err_msg)
        return True # close the connection
    
    # send the response
    send_headers = {"Content-Type": "application/json"}
    if force_close:
        send_headers["Connection"] = "Close"
    send_http_response(client_socket, 200, send_headers, json.dumps(response_json).encode())
    return force_close

class ThreadedAPIServer(AbstractAPIServer):
    """Threaded API server implementation."""
    lock: threading.Lock

    def __init__(self,
                 host: str, port: int,
                 credentials: dict[str, str],
                 request_callback: Callable[[str, str, dict[str, Any]], tuple[bool, dict[str, Any]]],
                 session_validity_callback: Optional[Callable[[LoginSession], bool]]=None,
                 login_cookie_level: str=utils.STRICT,
                 logger: Optional[logging.Logger] = None,
                 timeout: float=5.0,
                 max_recv_calls_per_request: int=1024) -> None:
        """
        Initialize the API server with the given host and port.

        :param host: The host to bind the server to.
        :param port: The port to bind the server to.
        :param credentials: Dictionary of credentials to use for login.
        :param request_callback: Callback function to handle logged in requests, where the input is the username, session token and request body JSON dictionary
            and the output is a boolean representing whether to force_close and response body JSON dictionary. This callback is asynchronous, and should be
            thread or process safe. This means that the callback be a function directly contained in some .py file, so that subprocesses can import it.
            For example, the callback signature could be: `def request_callback(username: str, session_token: str, data: dict[str, Any]) -> [bool, dict[str, Any]]`.
        :param session_validity_callback: Callback function to check the validity of a session, where the input is the login session object, and the output is a
            boolean representing the validity of the session. The server will call this function periodically, and/or when a request with the session token is
            made, to check the validity of the session. This function will be called synchronously in the main server thread/process, so it should be fast.
            For example, the callback signature could be: `def session_validity_callback(login_session: LoginSession) -> bool`.
        :param login_cookie_level: Level of the login cookie. Default is STRICT. See utils.py for more information.
        :param logger: Optional logger to use for logging.
        :param timeout: Timeout for socket operations. Default is 5 seconds.
        :param max_recv_calls_per_request: Maximum number of recv calls to make for a single request. Default is 1024, correpsonding to 4MB (4096 bytes * 1024).
        """
        super().__init__(host, port, credentials, request_callback, session_validity_callback, login_cookie_level, logger, timeout, max_recv_calls_per_request)
        self.lock = threading.Lock()
    
    def mainLoopImpl(self, server_socket: socket.socket) -> None:
        self.SERVER_RUNNING = True
        client_threads: list[tuple[threading.Thread, _ThreadFlags]] = []
        try:
            while self.SERVER_RUNNING:
                # remove the finished threads
                idx = 0
                while idx < len(client_threads):
                    if not client_threads[idx][0].is_alive():
                        reason = client_threads[idx][1]
                        client_threads.pop(idx)
                        self.logger.debug("Client thread for {}:{} finished. Reason: {}".format(reason.address[0], reason.address[1], reason.exit_reason))
                    else:
                        idx += 1 # go next if its alive
                
                # clean the sessions
                with self.lock:
                    # invalidate sessions based on validity callback
                    if self.session_validity_callback is not None:
                        for key in self.sessions.session_dict:
                            if not self.session_validity_callback(self.sessions.session_dict[key]):
                                self.sessions.session_dict[key].invalidate()
                    
                    # now remove the invalid sessions
                    num_cleaned, num_remaining, removed_sessions =self.sessions.clean_sessions()
                    if num_cleaned > 0:
                        for session in removed_sessions:
                            self.logger.info("Session for user {} with session token {} logged out.".format(session.get_username(), session.get_hashed_session_token()))
                        self.logger.info("Cleaned up {} sessions. {} sessions remaining.".format(num_cleaned, num_remaining))
                
                # accept a new connection
                try:
                    client_socket, addr = server_socket.accept()
                except socket.timeout:
                    continue
                
                self.logger.debug("Accepted connection from {}:{}".format(addr[0], addr[1]))
                client_socket.settimeout(self.timeout) # set the timeout for the client socket
                if self.context is not None: # wrap the socket in an SSL context, if necessary
                    try:
                        client_socket = self.context.wrap_socket(client_socket, server_side=True)
                    except ssl.SSLError as e: # handle SSL errors, and close and skip the connection
                        self.logger.error("Error setting up TLS connection from {}:{}".format(addr[0], addr[1]))
                        self.logger.error(traceback.format_exc())
                        client_socket.close() # close the socket
                        continue # skip the connection
                    except socket.timeout: # handle timeouts, and close and skip the connection
                        self.logger.error("Timeout setting up TLS connection from {}:{}".format(addr[0], addr[1]))
                        client_socket.close() # close the socket
                        continue
                
                # all set, handle the client in a new thread
                thread_flags = _ThreadFlags(addr)
                thrd = threading.Thread(target=handle_client, args=(client_socket, addr, self, thread_flags, self.getLoginParams())) # safe to pass self here since threads do not require pickling
                thrd.start()
                client_threads.append((thrd, thread_flags))
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received. Shutting down server.")
        except Exception as e:
            self.logger.error("Unexpected error in server loop.")
            self.logger.error(traceback.format_exc())
        finally:
            self.SERVER_RUNNING = False
            try:
                server_socket.close() # close the server socket
            except Exception:
                self.logger.error("Error closing server socket.")
                self.logger.error(traceback.format_exc())
        
        self.logger.info("Waiting for all client threads to finish...")
        self.logger.info("Remaining client threads: {}".format(len(client_threads)))
        for thrd, reason in client_threads:
            reason.stop_flag = True # signal the threads to stop
        for thrd, reason in client_threads:
            thrd.join()
        self.logger.info("All client threads finished. Server shutdown complete.")
    
    def generateSessionToken(self):
        with self.lock:
            return super().generateSessionToken()