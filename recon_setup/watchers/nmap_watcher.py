import os
import re
from threading import Event

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from recon_setup.utils.logger import write_log
from recon_setup.utils.scan import SCAN_COMPLETE
from recon_setup.utils.spray import start_spraying
from recon_setup.utils.tasks import handle_task


class NmapLogHandler(FileSystemEventHandler):
    """Watch the piped scan output for open ports and scan completion.

    The scan is the aliasr ``port scan all in one`` cheat (see
    :mod:`recon_setup.utils.scan`), so two output shapes carry ports:

    * **naabu (TCP)** prints one ``<ip>:<port>`` line per open port, for both
      the 1-10000 and 10001-65535 sweeps.
    * **nmap (UDP)** prints ``Discovered open port <port>/udp on <ip>``.

    A port is dispatched at most once (naabu can repeat it across sweeps, and a
    service such as DNS shows up on both TCP and UDP).  Completion is the
    :data:`~recon_setup.utils.scan.SCAN_COMPLETE` sentinel the launcher appends
    after the cheat.
    """

    def __init__(self, context):
        super().__init__()
        self.context = context
        self.last_position = 0
        self.completed = Event()  # Event to signal scan completion
        self._seen: set[str] = set()  # ports already dispatched
        self._tcp_re = re.compile(rf"^{re.escape(context.ip)}:(\d+)$")

    def _dispatch(self, port):
        """Run tasks for *port* once; ignore repeats."""
        if port in self._seen:
            return
        self._seen.add(port)
        handle_task(self.context, port)

    def on_modified(self, event):
        if event.src_path != self.context.tmux_pipe_file:
            return
        with open(self.context.tmux_pipe_file) as tmux_pipe_file:
            tmux_pipe_file.seek(self.last_position)
            new_lines = tmux_pipe_file.readlines()
            self.last_position = tmux_pipe_file.tell()
            for line in new_lines:
                stripped = line.strip()
                if SCAN_COMPLETE in line:
                    self.context.nmap_pane.cmd("pipe-pane")  # stop piping
                    self.completed.set()
                    break
                # naabu TCP: "<ip>:<port>"
                m = self._tcp_re.match(stripped)
                if m:
                    self._dispatch(m.group(1))
                    continue
                # nmap UDP: "Discovered open port <port>/udp on <ip>"
                if "Discovered open port" in line and "/udp" in line:
                    self._dispatch(line.split()[3].split("/")[0])


def watch_nmap(context):
    # Initialize nmap log handler and observer
    event_handler = NmapLogHandler(context)
    observer = Observer()
    observer.schedule(
        event_handler, path=os.path.dirname(context.tmux_pipe_file), recursive=False
    )
    # Start the observer
    observer.start()
    try:
        event_handler.completed.wait()
    except Exception as e:
        write_log(context.log_file, f"Nmap observer interrupted: {str(e)}", "ERROR")
    finally:
        write_log(
            context.log_file, "Initial nmap scan complete - stopping nmap observer"
        )
        observer.stop()
        observer.join()
        if context.is_ad:
            write_log(
                context.log_file,
                "Machine identified as domain controller, watching for credentials to spray...",
            )
            start_spraying(context)
