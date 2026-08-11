import unittest
from types import SimpleNamespace
from unittest.mock import patch

import server
from pipeline.jml_to_dafny import UnsupportedBoundary
from pipeline.schemas import VC


SOURCE = "public class Worker {}"


class Socket:
    def __init__(self):
        self.events = []

    async def send_json(self, event):
        self.events.append(event)


class ServerWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_with_events_deterministically_drains_callback_queue(self):
        socket = Socket()

        def worker(value, on_event=None):
            on_event({"type": "progress", "value": value})
            on_event({"type": "complete", "status": "OK"})
            return "done"

        async def controlled_to_thread(function, *args, **kwargs):
            result = function(*args, **kwargs)
            # Yield so call_soon_threadsafe publications are committed before completion.
            await server.asyncio.sleep(0)
            return result

        with patch.object(server.asyncio, "to_thread", side_effect=controlled_to_thread):
            result = await server._run_with_events(socket, worker, 7)
        self.assertEqual(result, "done")
        self.assertEqual([event["type"] for event in socket.events], ["progress", "complete"])

    def test_verify_source_success_failure_fallback_and_vacuous(self):
        events = []
        with (patch.object(server, "verify", return_value=(0, "clean")),
              patch.object(server, "parse_check", return_value=[])):
            self.assertEqual(server._verify_source(SOURCE, "check", events.append), "VERIFIED")
        self.assertEqual(events[-1]["type"], "verified")

        events = []
        with (patch.object(server, "verify", return_value=(1, "unparsed error")),
              patch.object(server, "parse_check", return_value=[])):
            self.assertEqual(server._verify_source(SOURCE, "check", events.append), "COMPILE_FAILED")
        self.assertEqual(events[1]["type"], "vc_failure")
        self.assertEqual(events[-1]["failures"], 1)

        events = []
        with (patch.object(server, "verify", return_value=(0, "dropped")),
              patch.object(server, "parse_vcs", return_value=[]),
              patch.object(server, "has_dropped_vc", return_value=True)):
            self.assertEqual(server._verify_source(SOURCE, "esc", events.append), "VACUOUS_VERIFIED")
        self.assertEqual(events[-1]["type"], "complete")

    def test_verify_source_auto_jml_success_and_plain_failure(self):
        events = []
        with (patch.object(server, "verify", return_value=(0, "proved")),
              patch.object(server, "has_dropped_vc", return_value=False)):
            self.assertEqual(server._verify_source_auto(SOURCE, events.append), "VERIFIED")
        self.assertEqual(events[-1]["backend"], "jml")

        events = []
        vc = VC("Worker.java", 3, "Postcondition", detail="failed")
        with (patch.object(server, "verify", return_value=(6, "failed")),
              patch.object(server, "detect_boundary", return_value=None),
              patch.object(server, "parse_vcs", return_value=[vc])):
            self.assertEqual(server._verify_source_auto(SOURCE, events.append), "VERIFY_FAILED")
        self.assertTrue(any(event["type"] == "vc_failure" for event in events))
        self.assertEqual(events[-1]["failures"], 1)

        events = []
        with (patch.object(server, "verify", return_value=(0, "dropped obligation")),
              patch.object(server, "has_dropped_vc", return_value=True),
              patch.object(server, "detect_boundary", return_value=None),
              patch.object(server, "parse_vcs", return_value=[])):
            self.assertEqual(
                server._verify_source_auto(SOURCE, events.append), "VACUOUS_VERIFIED")
        self.assertEqual(events[-1]["type"], "complete")

    def test_verify_source_auto_dafny_success_and_rejection(self):
        translation = SimpleNamespace(boundary="heap_snapshot", dafny_code="method R() {}",
                                      rewrites=["snapshot"])
        result = SimpleNamespace(status="VERIFIED", exit_code=0, output="proved",
                                 translation=translation)
        events = []
        with (patch.object(server, "verify", return_value=(6, "failed")),
              patch.object(server, "detect_boundary", return_value="heap_snapshot"),
              patch.object(server, "translate_and_verify", return_value=result)):
            self.assertEqual(server._verify_source_auto(SOURCE, events.append), "VERIFIED")
        self.assertEqual(events[-1]["type"], "dafny_result")

        events = []
        with (patch.object(server, "verify", return_value=(6, "failed")),
              patch.object(server, "detect_boundary", return_value="heap_snapshot"),
              patch.object(server, "translate_and_verify",
                           side_effect=UnsupportedBoundary("ambiguous"))):
            self.assertEqual(server._verify_source_auto(SOURCE, events.append), "VERIFY_FAILED")
        self.assertIn("rejected", events[-1]["message"])


if __name__ == "__main__":
    unittest.main()
