#!/usr/bin/env python3
"""
Higgsfield Lipsync Pipeline
Automates video lipsync using Higgsfield's internal API (fnf.higgsfield.ai).

Flow:
  1. Upload base video → get CDN URL
  2. Generate TTS audio (with name replacing "watermelon") → get audio URL
  3. Submit Sync Lipsync 2 Pro job (video + audio) → get result video
  4. Download final video

Auth: Uses Clerk JWT from __session cookie (via cookie extractor or manual input).

Usage:
  python higgsfield_lipsync.py run \
    --video "/path/to/base-video.mp4" \
    --name "Johnathan Squirrel" \
    --token "eyJhb..."

  python higgsfield_lipsync.py run \
    --video "/path/to/base-video.mp4" \
    --name "Johnathan Squirrel" \
    --cookie-file cookies.json

  python higgsfield_lipsync.py voices --token "eyJhb..."
  python higgsfield_lipsync.py status --job-id "abc-123" --token "eyJhb..."

  # Voice cloning
  python higgsfield_lipsync.py clone-voice \
    --sample voice-sample.mp3 \
    --name "Kishore" \
    --client-cookie-file /tmp/higgsfield_client_cookie.txt

  python higgsfield_lipsync.py list-clones \
    --client-cookie-file /tmp/higgsfield_client_cookie.txt
"""

import argparse
import base64
import json
import os
import random
import sys
import time
from pathlib import Path

import requests

# ── Config ──────────────────────────────────────────────────────────────────

BASE_URL = "https://fnf.higgsfield.ai"
CLERK_FAPI = "https://clerk.higgsfield.ai"

DEFAULT_SCRIPT = (
    "Hey {name}! Quick hello before Funders Forum. "
    "What if your underwriting team could handle twice the volume "
    "without adding headcount? We've been deep in helping teams "
    "do that at scale. Swing by our booth, we've got iPads to "
    "give away. Would love fifteen minutes."
)

DEFAULT_VOICE_ID = "6pBuGbellIksHKibt0je2n"  # Marston - Middle Age Male

TTS_PARAMS = {
    "similarity_boost": 90,
    "preset_name": "",
    "style": 60,
    "speed": 1.1,
    "stability": 30,
}

LIPSYNC_PARAMS = {
    "type": "sync-so",
    "quality": "high",
    "temperature": 0.5,
    "sync_mode": "bounce",
    "active_speaker_detection": False,
    "prompt": "",
    "enhance": False,
    "styleId": None,
}

POLL_INTERVAL = 5  # seconds between status checks
MAX_POLL_TIME = 600  # 10 minutes max wait


# ── Clerk Token Manager ─────────────────────────────────────────────────────

class ClerkTokenManager:
    """Manages Clerk JWT tokens with automatic refresh using __client cookie."""

    def __init__(self, client_cookie: str = None, session_id: str = None,
                 static_token: str = None):
        self._client_cookie = client_cookie
        self._session_id = session_id
        self._static_token = static_token
        self._cached_token = static_token
        self._token_expiry = 0

    def get_token(self) -> str:
        """Get a fresh JWT token, refreshing if needed."""
        now = time.time()

        # If we have a cached token that's still valid (with 10s buffer)
        if self._cached_token and self._token_expiry > now + 10:
            return self._cached_token

        # If we can refresh via __client cookie
        if self._client_cookie and self._session_id:
            return self._refresh_token()

        # If we have a static token (might be expired), use it anyway
        if self._cached_token:
            return self._cached_token

        raise RuntimeError("No token available and cannot refresh")

    def _refresh_token(self) -> str:
        """Refresh JWT using Clerk FAPI with __client cookie."""
        url = f"{CLERK_FAPI}/v1/client/sessions/{self._session_id}/tokens"
        resp = requests.post(
            url,
            headers={"Content-Type": "application/json"},
            cookies={"__client": self._client_cookie},
        )
        resp.raise_for_status()
        data = resp.json()
        jwt = data.get("jwt")
        if not jwt:
            raise RuntimeError(f"No JWT in Clerk response: {data}")

        self._cached_token = jwt
        # Decode expiry from JWT payload
        try:
            payload_b64 = jwt.split(".")[1]
            # Add padding
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            self._token_expiry = payload.get("exp", 0)
        except Exception:
            self._token_expiry = time.time() + 50  # assume 50s if decode fails

        return jwt

    @classmethod
    def from_client_cookie(cls, client_cookie: str, session_id: str = None):
        """Create manager from __client cookie. Auto-detects session_id if not provided."""
        mgr = cls(client_cookie=client_cookie, session_id=session_id or "unknown")
        if not session_id:
            # Get session ID by refreshing with a dummy session list
            # Actually, we need to call /v1/client first to get sessions
            resp = requests.get(
                f"{CLERK_FAPI}/v1/client",
                cookies={"__client": client_cookie},
            )
            resp.raise_for_status()
            client_data = resp.json()
            sessions = client_data.get("response", {}).get("sessions", [])
            if not sessions:
                raise RuntimeError("No active Clerk sessions found")
            # Use the first active session
            for s in sessions:
                if s.get("status") == "active":
                    mgr._session_id = s["id"]
                    break
            else:
                mgr._session_id = sessions[0]["id"]
        return mgr

    @classmethod
    def from_static_token(cls, token: str):
        """Create manager from a static JWT (no refresh capability)."""
        mgr = cls(static_token=token)
        try:
            payload_b64 = token.split(".")[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            mgr._token_expiry = payload.get("exp", 0)
            mgr._session_id = payload.get("sid")
        except Exception:
            pass
        return mgr


# ── API Client ──────────────────────────────────────────────────────────────

class HiggsFieldAPI:
    def __init__(self, token_manager: ClerkTokenManager):
        self.token_manager = token_manager
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self._update_auth()

    def _update_auth(self):
        """Refresh the auth header with a fresh token."""
        token = self.token_manager.get_token()
        self.session.headers["Authorization"] = f"Bearer {token}"

    def _url(self, path: str) -> str:
        return f"{BASE_URL}{path}"

    def get_user(self) -> dict:
        """Get user info and credit balance."""
        self._update_auth()
        resp = self.session.get(self._url("/user"))
        resp.raise_for_status()
        return resp.json()

    # ── Media Upload ────────────────────────────────────────────────────

    def upload_video(self, file_path: str) -> dict:
        """Upload a video file via POST /video → PUT → POST /video/{id}/upload.
        Returns {id, url, type: "video_input"}."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        ext = path.suffix.lower()
        mimetype_map = {
            ".mp4": "video/mp4", ".webm": "video/webm",
            ".mov": "video/quicktime", ".avi": "video/x-msvideo",
        }
        mimetype = mimetype_map.get(ext, "video/mp4")

        print(f"  [1/3] Creating presigned URL for {path.name} ({mimetype})...")
        self._update_auth()
        resp = self.session.post(
            self._url("/video"),
            json={"mimetype": mimetype},
        )
        resp.raise_for_status()
        media_info = resp.json()
        media_id = media_info["id"]
        upload_url = media_info["upload_url"]
        content_type = media_info.get("content_type", mimetype)
        media_url = media_info["url"]

        print(f"  [2/3] Uploading {path.name} ({path.stat().st_size / 1024 / 1024:.1f} MB)...")
        with open(file_path, "rb") as f:
            upload_resp = requests.put(
                upload_url,
                data=f,
                headers={"Content-Type": content_type},
            )
            upload_resp.raise_for_status()

        print(f"  [3/3] Confirming upload...")
        self._update_auth()
        confirm_resp = self.session.post(self._url(f"/video/{media_id}/upload"))
        confirm_resp.raise_for_status()

        print(f"  Upload complete: {media_url[:80]}...")
        return {"id": media_id, "url": media_url, "type": "video_input"}

    def upload_audio(self, file_path: str) -> dict:
        """Upload an audio file via POST /audio → PUT → POST /audio/{id}/upload.
        Returns {id, url, type: "audio_input"}."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        ext = path.suffix.lower().lstrip(".")
        name = path.stem
        content_type_map = {
            "mp3": "audio/mpeg", "wav": "audio/wav",
            "m4a": "audio/mp4", "ogg": "audio/ogg",
            "webm": "audio/webm", "flac": "audio/flac",
        }

        print(f"  [1/3] Creating presigned URL for {path.name}...")
        self._update_auth()
        resp = self.session.post(
            self._url("/audio"),
            json={"name": name, "extension": ext},
        )
        resp.raise_for_status()
        media_info = resp.json()
        media_id = media_info["id"]
        upload_url = media_info["upload_url"]
        fallback_ct = content_type_map.get(ext, "audio/mpeg")
        content_type = media_info.get("content_type", fallback_ct)
        media_url = media_info["url"]

        print(f"  [2/3] Uploading {path.name} ({path.stat().st_size / 1024 / 1024:.1f} MB)...")
        with open(file_path, "rb") as f:
            upload_resp = requests.put(
                upload_url,
                data=f,
                headers={"Content-Type": content_type},
            )
            upload_resp.raise_for_status()

        print(f"  [3/3] Confirming upload...")
        self._update_auth()
        confirm_resp = self.session.post(self._url(f"/audio/{media_id}/upload"))
        confirm_resp.raise_for_status()

        print(f"  Upload complete: {media_url[:80]}...")
        return {"id": media_id, "url": media_url, "type": "audio_input"}

    # ── Voice Cloning ────────────────────────────────────────────────────

    def get_voice_clones(self) -> list:
        """List all voice clones (built-in + user-created)."""
        self._update_auth()
        resp = self.session.get(self._url("/voice-clone"))
        resp.raise_for_status()
        data = resp.json()
        # API returns paginated: {items: [...], has_more: bool}
        if isinstance(data, dict) and "items" in data:
            return data["items"]
        return data

    def clone_voice(self, audio_inputs: list, name: str = None) -> dict:
        """Create a voice clone from audio samples.

        Args:
            audio_inputs: List of {id, url, type: "audio_input"} dicts
            name: Optional name for the clone

        Returns:
            Voice clone object with id, status, etc.
        """
        payload = {"input_audios": audio_inputs}
        if name:
            payload["name"] = name

        print(f"  Submitting voice clone request ({len(audio_inputs)} audio sample(s))...")
        self._update_auth()
        resp = self.session.post(
            self._url("/voice-clone"),
            json=payload,
        )
        if resp.status_code >= 400:
            print(f"  ERROR {resp.status_code}: {resp.text[:500]}")
        resp.raise_for_status()
        clone = resp.json()
        clone_id = clone.get("id", "unknown")
        status = clone.get("status", "unknown")
        print(f"  Voice clone created: {clone_id} (status: {status})")
        return clone

    def poll_voice_clone(self, clone_id: str, poll_interval: int = 5,
                         max_wait: int = 300) -> dict:
        """Poll voice clone until ready."""
        start_time = time.time()
        last_status = None

        while True:
            elapsed = time.time() - start_time
            if elapsed > max_wait:
                raise TimeoutError(
                    f"Voice clone {clone_id} timed out after {max_wait}s"
                )

            self._update_auth()
            clones = self.get_voice_clones()
            clone = None
            for c in clones:
                if c.get("id") == clone_id:
                    clone = c
                    break

            if not clone:
                raise RuntimeError(f"Voice clone {clone_id} not found")

            status = clone.get("status", "unknown")
            if status != last_status:
                print(f"  Clone {clone_id[:8]}... status: {status} "
                      f"({elapsed:.0f}s elapsed)")
                last_status = status

            if status == "ready":
                return clone
            elif status in ("failed", "error"):
                raise RuntimeError(f"Voice clone {clone_id} failed: {clone}")

            time.sleep(poll_interval)

    # ── TTS ─────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_job_id(response_data: dict) -> str:
        """Extract the actual job ID from a nested API response.

        Responses have structure: {id: project_id, job_sets: [{id: set_id, jobs: [{id: job_id}]}]}
        The job_id inside jobs[] is what we need to poll at /jobs/{job_id}.
        """
        # Try nested path first: job_sets[0].jobs[0].id
        job_sets = response_data.get("job_sets", [])
        if job_sets:
            jobs = job_sets[0].get("jobs", [])
            if jobs:
                return jobs[0]["id"]
            # Fall back to job_set id
            return job_sets[0]["id"]
        # Direct job response
        return response_data.get("id") or response_data.get("job_set_id")

    def generate_tts(self, script: str, voice_id: str = DEFAULT_VOICE_ID,
                     sound_id: str = "") -> dict:
        """Generate TTS audio. Returns completed job with audio URLs."""
        params = {
            "voice_id": voice_id,
            "sound_id": sound_id,
            "prompt": script,
            **TTS_PARAMS,
        }
        print(f"  Submitting TTS job (voice: {voice_id})...")
        self._update_auth()
        resp = self.session.post(
            self._url("/jobs/text2speech"),
            json={"params": params},
        )
        resp.raise_for_status()
        data = resp.json()
        job_id = self._extract_job_id(data)
        print(f"  TTS job created: {job_id}")
        return self.poll_job(job_id)

    # ── Lipsync ─────────────────────────────────────────────────────────

    def submit_lipsync(self, video_input: dict, audio_input: dict) -> dict:
        """Submit Sync Lipsync 2 Pro job. Returns completed job.

        Args:
            video_input: {id, url, type} object (type: "video_input" or job type)
            audio_input: {id, url, type} object (type: "text2speech_job" or "audio_input")
        """
        seed = random.randint(1, 999999999)
        params = {
            **LIPSYNC_PARAMS,
            "input_video": video_input,
            "input_audio": audio_input,
            "input_image": None,
            "seed": seed,
        }
        print(f"  Submitting lipsync job (sync-so, seed={seed})...")
        self._update_auth()
        resp = self.session.post(
            self._url("/jobs/sync-so"),
            json={"params": params, "client_meta": {}},
        )
        if resp.status_code >= 400:
            print(f"  ERROR {resp.status_code}: {resp.text[:500]}")
        resp.raise_for_status()
        job = resp.json()
        job_id = self._extract_job_id(job)
        print(f"  Lipsync job created: {job_id}")
        return self.poll_job(job_id)

    # ── Job Polling ─────────────────────────────────────────────────────

    def get_job(self, job_id: str) -> dict:
        """Get job status and results."""
        self._update_auth()
        resp = self.session.get(self._url(f"/jobs/{job_id}"))
        resp.raise_for_status()
        return resp.json()

    def poll_job(self, job_id: str) -> dict:
        """Poll job until completed or failed."""
        start_time = time.time()
        last_status = None

        while True:
            elapsed = time.time() - start_time
            if elapsed > MAX_POLL_TIME:
                raise TimeoutError(
                    f"Job {job_id} timed out after {MAX_POLL_TIME}s"
                )

            job = self.get_job(job_id)
            status = job.get("status", "unknown")

            if status != last_status:
                print(f"  Job {job_id[:8]}... status: {status} "
                      f"({elapsed:.0f}s elapsed)")
                last_status = status

            if status == "completed":
                return job
            elif status in ("failed", "error", "cancelled"):
                error = job.get("error") or job.get("detail") or "Unknown error"
                raise RuntimeError(f"Job {job_id} failed: {error}")

            time.sleep(POLL_INTERVAL)

    # ── Voices ──────────────────────────────────────────────────────────

    def get_voices(self) -> list:
        """List available TTS voices."""
        self._update_auth()
        resp = self.session.get(self._url("/voices/"))
        resp.raise_for_status()
        return resp.json()

    # ── Download ────────────────────────────────────────────────────────

    @staticmethod
    def download_file(url: str, output_path: str):
        """Download a file from URL to local path."""
        print(f"  Downloading to {output_path}...")
        resp = requests.get(url, stream=True)
        resp.raise_for_status()
        total = int(resp.headers.get("content-length", 0))
        downloaded = 0
        with open(output_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
                downloaded += len(chunk)
                if total:
                    pct = downloaded / total * 100
                    print(f"\r  {downloaded / 1024 / 1024:.1f} MB / "
                          f"{total / 1024 / 1024:.1f} MB ({pct:.0f}%)",
                          end="", flush=True)
        print()  # newline after progress


# ── Token helpers ───────────────────────────────────────────────────────────

def get_token_from_cookie_file(cookie_file: str) -> str:
    """Extract Clerk __session token from cookie extractor JSON."""
    with open(cookie_file, "r") as f:
        cookies = json.load(f)

    # Cookie extractor stores cookies as a list of cookie objects
    if isinstance(cookies, list):
        for cookie in cookies:
            name = cookie.get("name", "")
            if name == "__session":
                return cookie["value"]

    # Or it might be a dict keyed by domain
    if isinstance(cookies, dict):
        for domain, domain_cookies in cookies.items():
            if isinstance(domain_cookies, list):
                for cookie in domain_cookies:
                    if cookie.get("name") == "__session":
                        return cookie["value"]
            elif isinstance(domain_cookies, dict):
                if "__session" in domain_cookies:
                    return domain_cookies["__session"]

    raise ValueError(
        "Could not find __session cookie in cookie file. "
        "Make sure the cookie extractor has captured higgsfield.ai cookies."
    )


def extract_result_url(job: dict, media_type: str = "video") -> str:
    """Extract the output URL from a completed job's results."""
    results = job.get("results")
    if not results:
        result = job.get("result")
        if result and isinstance(result, dict):
            url = result.get("url")
            if url:
                return url
        raise ValueError(f"No results in job: {json.dumps(job, indent=2)[:500]}")

    # TTS jobs have results.raw.url and results.sfx.url
    if isinstance(results, dict):
        if "raw" in results and isinstance(results["raw"], dict):
            return results["raw"]["url"]
        if "url" in results:
            return results["url"]
        # Lipsync jobs might have different structure
        for key, val in results.items():
            if isinstance(val, dict) and "url" in val:
                return val["url"]
            if isinstance(val, str) and val.startswith("http"):
                return val

    raise ValueError(f"Could not find URL in results: {json.dumps(results, indent=2)[:500]}")


# ── Pipeline ────────────────────────────────────────────────────────────────

def run_pipeline(video_path: str, name: str, token_manager: ClerkTokenManager,
                 script: str = None, voice_id: str = DEFAULT_VOICE_ID,
                 output_dir: str = "output", skip_tts: bool = False,
                 audio_url: str = None, video_url: str = None):
    """Run the full lipsync pipeline."""

    api = HiggsFieldAPI(token_manager)

    # Verify auth
    print("\n=== Verifying authentication ===")
    try:
        user = api.get_user()
        credits = user.get("subscription_credits", "?")
        print(f"  Authenticated as: {user.get('username', 'unknown')}")
        print(f"  Credits: {credits}")
    except requests.HTTPError as e:
        if e.response.status_code == 401:
            print("  ERROR: Token expired or invalid. Get a fresh token from:")
            print("    Browser console: await window.Clerk.session.getToken()")
            sys.exit(1)
        raise

    # Build personalized script
    if script is None:
        script = DEFAULT_SCRIPT
    personalized_script = script.replace("{name}", name)
    print(f"\n=== Script ===")
    print(f"  {personalized_script[:200]}...")

    # Step 1: Get video input object {id, url, type}
    if video_url:
        print(f"\n=== Step 1: Using provided video URL (re-uploading) ===")
        print(f"  Downloading from: {video_url[:80]}...")
        # Download CDN video to temp file, then upload via /video endpoint
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
        dl_resp = requests.get(video_url, stream=True)
        dl_resp.raise_for_status()
        for chunk in dl_resp.iter_content(chunk_size=8192):
            tmp.write(chunk)
        tmp.close()
        video_input = api.upload_video(tmp.name)
        os.unlink(tmp.name)
    elif video_path:
        print(f"\n=== Step 1: Upload video ===")
        video_input = api.upload_video(video_path)
        video_url = video_input["url"]
    else:
        raise ValueError("No video provided. Use --video or --video-url")

    # Step 2: Generate TTS (or use provided audio URL) → get audio input object
    if audio_url:
        print(f"\n=== Step 2: Using provided audio URL ===")
        print(f"  {audio_url[:80]}...")
        audio_input = {"id": "provided", "url": audio_url, "type": "audio_input"}
    elif skip_tts:
        print(f"\n=== Step 2: TTS skipped ===")
        audio_input = None
    else:
        print(f"\n=== Step 2: Generate TTS audio ===")
        tts_job = api.generate_tts(personalized_script, voice_id)
        tts_audio_url = extract_result_url(tts_job, "audio")
        tts_job_id = tts_job.get("id")
        print(f"  TTS audio: {tts_audio_url[:80]}...")
        audio_input = {"id": tts_job_id, "url": tts_audio_url, "type": "text2speech_job"}

    # Step 3: Submit lipsync
    print(f"\n=== Step 3: Submit lipsync job ===")
    if audio_input is None:
        raise ValueError("No audio available. Generate TTS or provide --audio-url")
    lipsync_job = api.submit_lipsync(video_input, audio_input)

    # Step 4: Extract result
    print(f"\n=== Step 4: Download result ===")
    result_url = extract_result_url(lipsync_job, "video")
    print(f"  Result URL: {result_url[:100]}...")

    # Download
    os.makedirs(output_dir, exist_ok=True)
    safe_name = name.replace(" ", "_").lower()
    output_path = os.path.join(output_dir, f"{safe_name}.mp4")
    api.download_file(result_url, output_path)

    print(f"\n=== DONE ===")
    print(f"  Output: {output_path}")
    print(f"  Job ID: {lipsync_job.get('id', 'unknown')}")

    return {
        "output_path": output_path,
        "result_url": result_url,
        "job_id": lipsync_job.get("id"),
        "audio_input": audio_input,
        "video_input": video_input,
    }


# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Higgsfield Lipsync Pipeline - Personalized video generation"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Common auth args for all subcommands
    def add_auth_args(p):
        p.add_argument("--token", help="Clerk JWT token (short-lived, 60s)")
        p.add_argument("--client-cookie", help="Clerk __client cookie (long-lived, enables auto-refresh)")
        p.add_argument("--client-cookie-file", help="File containing __client cookie value")
        p.add_argument("--session-id", help="Clerk session ID (auto-detected if not provided)")

    # run command
    run_parser = subparsers.add_parser("run", help="Run the full lipsync pipeline")
    video_group = run_parser.add_mutually_exclusive_group(required=True)
    video_group.add_argument("--video", help="Path to base video file (will be uploaded)")
    video_group.add_argument("--video-url", help="URL of video already on CDN (skips upload)")
    run_parser.add_argument("--name", required=True, help="Recipient name (replaces placeholder)")
    run_parser.add_argument("--script", help="Custom script (use {name} as placeholder)")
    run_parser.add_argument("--voice-id", default=DEFAULT_VOICE_ID, help="TTS voice ID")
    run_parser.add_argument("--audio-url", help="Pre-generated audio URL (skips TTS)")
    run_parser.add_argument("--output-dir", default="output", help="Output directory")
    add_auth_args(run_parser)

    # voices command
    voices_parser = subparsers.add_parser("voices", help="List available TTS voices")
    add_auth_args(voices_parser)

    # status command
    status_parser = subparsers.add_parser("status", help="Check job status")
    status_parser.add_argument("--job-id", required=True, help="Job ID to check")
    add_auth_args(status_parser)

    # clone-voice command
    clone_parser = subparsers.add_parser("clone-voice", help="Clone a voice from audio sample(s)")
    clone_parser.add_argument("--sample", required=True, nargs="+",
                              help="Path(s) to audio sample file(s) (mp3/wav/m4a)")
    clone_parser.add_argument("--name", help="Name for the cloned voice")
    clone_parser.add_argument("--wait", action="store_true", default=True,
                              help="Wait for clone to be ready (default: true)")
    clone_parser.add_argument("--no-wait", dest="wait", action="store_false",
                              help="Don't wait for clone to finish processing")
    add_auth_args(clone_parser)

    # list-clones command
    clones_parser = subparsers.add_parser("list-clones", help="List voice clones")
    add_auth_args(clones_parser)

    # credits command
    credits_parser = subparsers.add_parser("credits", help="Check credit balance")
    add_auth_args(credits_parser)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Build token manager
    token_manager = _build_token_manager(args)

    if args.command == "run":
        run_pipeline(
            video_path=args.video,
            name=args.name,
            token_manager=token_manager,
            script=args.script,
            voice_id=args.voice_id,
            output_dir=args.output_dir,
            audio_url=args.audio_url,
            video_url=args.video_url,
        )

    elif args.command == "voices":
        api = HiggsFieldAPI(token_manager)
        voices = api.get_voices()
        if isinstance(voices, list):
            print(f"\nAvailable voices ({len(voices)}):")
            for v in voices:
                vid = v.get("id", "?")
                vname = v.get("name", "?")
                desc = v.get("description", "")
                print(f"  {vid}  {vname}  {desc[:50]}")
        else:
            print(json.dumps(voices, indent=2))

    elif args.command == "status":
        api = HiggsFieldAPI(token_manager)
        job = api.get_job(args.job_id)
        print(json.dumps({
            "id": job.get("id"),
            "status": job.get("status"),
            "type": job.get("job_set_type"),
            "created_at": job.get("created_at"),
        }, indent=2))
        if job.get("status") == "completed":
            try:
                url = extract_result_url(job)
                print(f"\nResult URL: {url}")
            except ValueError:
                print("\nNo result URL found")

    elif args.command == "clone-voice":
        api = HiggsFieldAPI(token_manager)

        # Upload each audio sample
        audio_inputs = []
        for sample_path in args.sample:
            print(f"\n--- Uploading audio sample: {sample_path} ---")
            audio_obj = api.upload_audio(sample_path)
            audio_inputs.append(audio_obj)

        # Submit voice clone
        print(f"\n--- Creating voice clone ---")
        clone = api.clone_voice(audio_inputs, name=args.name)
        clone_id = clone.get("id")

        if args.wait and clone.get("status") != "ready":
            print(f"\n--- Waiting for clone to be ready ---")
            clone = api.poll_voice_clone(clone_id)

        print(f"\n=== Voice Clone Result ===")
        print(f"  ID:     {clone.get('id')}")
        print(f"  Name:   {clone.get('name', 'unnamed')}")
        print(f"  Status: {clone.get('status')}")
        print(f"\n  Use this voice with: --voice-id {clone.get('id')}")

    elif args.command == "list-clones":
        api = HiggsFieldAPI(token_manager)
        clones = api.get_voice_clones()
        if isinstance(clones, list):
            print(f"\nVoice clones ({len(clones)}):")
            for c in clones:
                cid = c.get("id", "?")
                cname = c.get("name", "unnamed")
                status = c.get("status", "?")
                internal = " (built-in)" if c.get("is_internal") else ""
                print(f"  {cid}  {cname}  [{status}]{internal}")
        else:
            print(json.dumps(clones, indent=2))

    elif args.command == "credits":
        api = HiggsFieldAPI(token_manager)
        user = api.get_user()
        print(json.dumps({
            "username": user.get("username"),
            "subscription_credits": user.get("subscription_credits"),
            "plan_type": user.get("plan_type"),
        }, indent=2))


def _build_token_manager(args) -> ClerkTokenManager:
    """Build a ClerkTokenManager from CLI args or env vars."""
    # Priority 1: __client cookie (supports auto-refresh)
    client_cookie = getattr(args, "client_cookie", None)
    if not client_cookie:
        ccf = getattr(args, "client_cookie_file", None)
        if ccf and os.path.exists(ccf):
            with open(ccf) as f:
                client_cookie = f.read().strip()
    if not client_cookie:
        client_cookie = os.environ.get("HIGGSFIELD_CLIENT_COOKIE")

    if client_cookie:
        session_id = getattr(args, "session_id", None)
        print("  Using __client cookie for auto-refreshing tokens")
        return ClerkTokenManager.from_client_cookie(client_cookie, session_id)

    # Priority 2: Static JWT token (expires in ~60s, no refresh)
    token = getattr(args, "token", None) or os.environ.get("HIGGSFIELD_TOKEN")
    if token:
        print("  Using static JWT token (expires in ~60s, no auto-refresh)")
        return ClerkTokenManager.from_static_token(token)

    print("ERROR: No authentication provided.")
    print("  Option 1 (recommended): --client-cookie-file /tmp/higgsfield_client_cookie.txt")
    print("  Option 2 (short-lived):  --token <jwt>")
    print("  Option 3: Set HIGGSFIELD_CLIENT_COOKIE or HIGGSFIELD_TOKEN env var")
    sys.exit(1)


if __name__ == "__main__":
    main()
