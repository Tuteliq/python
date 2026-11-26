"""What the client sends, checked on the wire with httpx's mock transport. Invented values only."""

import json
import warnings
from typing import Any

import httpx
import pytest

from tuteliq import (
    ActionPlanResult,
    ChipPolicy,
    CreateVerificationSessionInput,
    DocumentType,
    FaceMatchResult,
    GetActionPlanInput,
    Tuteliq,
    VerificationMode,
    VerificationSession,
    VerificationSessionStatus,
)


def client_with(handler: Any) -> tuple[Tuteliq, list[httpx.Request]]:
    """A client whose requests go to `handler` instead of the network, keeping its real headers."""
    sent: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return handler(request)

    client = Tuteliq(api_key="test-key-0000", max_retries=1)
    client._client._transport = httpx.MockTransport(record)
    return client, sent


SESSION = {
    "session_id": "sess_example_1",
    "mobile_url": "https://verify.example/s/abc",
    "expires_at": 1787253900000,
    "mode": "age",
    "chip_policy": "optional",
    "auto_capture": True,
}


class TestUploads:
    async def test_a_file_upload_is_sent_as_multipart(self) -> None:
        client, sent = client_with(lambda r: httpx.Response(200, json={"ok": True}))
        await client._multipart_request(
            "/api/v1/safety/image", {"k": "v"}, {"file": ("a.png", b"x", "image/png")}
        )
        assert sent[0].headers["content-type"].startswith("multipart/form-data; boundary=")

    async def test_a_json_request_is_sent_as_json(self) -> None:
        client, sent = client_with(lambda r: httpx.Response(201, json=SESSION))
        await client.create_verification_session(
            CreateVerificationSessionInput(mode=VerificationMode.AGE)
        )
        assert sent[0].headers["content-type"] == "application/json"


class TestCreateVerificationSession:
    async def body_for(self, input_data: CreateVerificationSessionInput) -> dict[str, Any]:
        client, sent = client_with(lambda r: httpx.Response(201, json=SESSION))
        await client.create_verification_session(input_data)
        body: dict[str, Any] = json.loads(sent[0].content)
        return body

    async def test_sends_the_fields_the_api_accepts(self) -> None:
        body = await self.body_for(
            CreateVerificationSessionInput(
                mode=VerificationMode.IDENTITY,
                document_type=DocumentType.PASSPORT,
                chip_policy=ChipPolicy.INSTEAD_OF_PHOTO,
                auto_capture=False,
            )
        )
        assert body == {
            "mode": "identity",
            "document_type": "passport",
            "chip_policy": "instead_of_photo",
            "auto_capture": False,
        }

    @pytest.mark.parametrize("document_type", [DocumentType.NATIONAL_ID, DocumentType.ID_CARD])
    async def test_a_national_id_card_is_sent_as_national_id(
        self, document_type: DocumentType
    ) -> None:
        # The API accepts passport, national_id and drivers_license.
        # ID_CARD stays as the old name for national_id.
        body = await self.body_for(
            CreateVerificationSessionInput(mode=VerificationMode.AGE, document_type=document_type)
        )
        assert body["document_type"] == "national_id"

    async def test_leaves_out_what_is_not_set(self) -> None:
        assert await self.body_for(CreateVerificationSessionInput(mode=VerificationMode.AGE)) == {
            "mode": "age"
        }

    async def test_fields_the_api_ignores_are_not_sent_and_warn(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            body = await self.body_for(
                CreateVerificationSessionInput(
                    mode=VerificationMode.AGE,
                    redirect_url="https://example.com/done",
                    external_id="user-1",
                )
            )
        assert body == {"mode": "age"}
        assert any(
            issubclass(w.category, DeprecationWarning) and "external_id" in str(w.message)
            for w in caught
        )

    def test_the_session_reads_chip_policy_and_auto_capture(self) -> None:
        session = VerificationSession.from_dict(SESSION)
        assert session.chip_policy == ChipPolicy.OPTIONAL
        assert session.auto_capture is True
        assert session.expires_at == 1787253900000

    def test_a_session_from_an_older_api_reads_without_them(self) -> None:
        older = {k: v for k, v in SESSION.items() if k not in ("chip_policy", "auto_capture")}
        session = VerificationSession.from_dict(older)
        assert session.chip_policy is None and session.auto_capture is None


class TestFaceMatchResult:
    def test_reads_match_score(self) -> None:
        face = FaceMatchResult.from_dict(
            {"matched": True, "distance": 0.45, "confidence": 0.55, "match_score": 0.94}
        )
        assert face.match_score == 0.94

    def test_reads_a_face_match_without_distance(self) -> None:
        # The age and session results leave the distance out.
        face = FaceMatchResult.from_dict({"matched": True, "confidence": 0.55})
        assert face.distance is None and face.match_score is None and face.matched is True


class TestSessionPoll:
    async def test_a_session_waiting_for_a_document_photo_is_read(self) -> None:
        polled = {"session_id": "sess_example_1", "status": "document_required"}
        client, _ = client_with(lambda r: httpx.Response(200, json=polled))
        result = await client.get_verification_session("sess_example_1")
        assert result.status == VerificationSessionStatus.DOCUMENT_REQUIRED


PLAN = {"audience": "parent", "steps": ["Stay calm."], "tone": "supportive"}


class TestActionPlan:
    async def body_for(self, input_data: GetActionPlanInput) -> dict[str, Any]:
        client, sent = client_with(lambda r: httpx.Response(200, json=PLAN))
        await client.get_action_plan(input_data)
        body: dict[str, Any] = json.loads(sent[0].content)
        return body

    async def test_sends_the_country(self) -> None:
        body = await self.body_for(GetActionPlanInput(situation="A worry", country="SE"))
        assert body["country"] == "SE"

    async def test_leaves_out_the_country_when_not_set(self) -> None:
        body = await self.body_for(GetActionPlanInput(situation="A worry"))
        assert "country" not in body

    def test_reads_general_guidance(self) -> None:
        result = ActionPlanResult.from_dict({**PLAN, "general_guidance": True})
        assert result.general_guidance is True

    def test_a_tailored_plan_is_not_general_guidance(self) -> None:
        assert ActionPlanResult.from_dict(PLAN).general_guidance is False
