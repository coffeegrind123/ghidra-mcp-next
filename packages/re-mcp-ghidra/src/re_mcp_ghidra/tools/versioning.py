# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Ghidra Server version control for the open program.

A program opened from ghidra://host/repo/path is a versioned file: readable
at once, writable (and savable) only after checkout_file.  checkin_file
publishes the changes as a new version.
"""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import ANNO_DESTRUCTIVE, ANNO_MUTATE, ANNO_READ_ONLY
from re_mcp_ghidra.session import session


class VersionState(BaseModel):
    path: str = Field(description="Program path inside the project or repository.")
    versioned: bool = Field(description="Under Ghidra Server version control.")
    checked_out: bool = Field(description="This user holds a checkout.")
    exclusive: bool = Field(description="The checkout is exclusive.")
    modified_since_checkout: bool = Field(description="Local changes not yet checked in.")
    version: int = Field(description="Version this copy is based on (-1 if unversioned).")
    latest_version: int = Field(description="Newest version on the server (-1 if unversioned).")
    can_save: bool = Field(description="save_database will succeed.")
    read_only: bool = Field(description="The program cannot be changed.")


class VersionEntry(BaseModel):
    version: int = Field(description="Version number.")
    user: str = Field(description="Who checked it in.")
    comment: str = Field(description="Check-in comment.")
    date: str = Field(description="When, ISO 8601.")


class VersionHistory(BaseModel):
    path: str = Field(description="Program path.")
    versions: list[VersionEntry] = Field(description="Oldest first.")


class AddedToRepository(BaseModel):
    url: str = Field(description="ghidra:// URL of the new versioned file; open_database opens it.")
    version: int = Field(description="Its server version (1 for a new file).")
    checked_out: bool = Field(description="Whether you kept a checkout of it.")


class CheckoutEntry(BaseModel):
    checkout_id: int = Field(description="Server checkout id.")
    user: str = Field(description="Who holds it.")
    version: int = Field(description="Version checked out.")
    exclusive: bool = Field(description="Exclusive checkout.")
    date: str = Field(description="When, ISO 8601.")
    project: str = Field(description="The holder's project path.")


class CheckoutList(BaseModel):
    path: str = Field(description="Program path.")
    checkouts: list[CheckoutEntry] = Field(description="Active checkouts by anyone.")


def _iso(millis: int) -> str:
    import datetime  # noqa: PLC0415

    return datetime.datetime.fromtimestamp(millis / 1000, tz=datetime.UTC).isoformat()


def _state() -> VersionState:
    df = session.domain_file
    versioned = bool(df.isVersioned())
    status = df.getCheckoutStatus() if df.isCheckedOut() else None
    return VersionState(
        path=str(df.getPathname()),
        versioned=versioned,
        checked_out=bool(df.isCheckedOut()),
        exclusive=bool(df.isCheckedOutExclusive()),
        modified_since_checkout=bool(df.modifiedSinceCheckout()) if status is not None else False,
        version=int(df.getVersion()) if versioned else -1,
        latest_version=int(df.getLatestVersion()) if versioned else -1,
        can_save=bool(df.canSave()),
        read_only=bool(df.isReadOnly()) or (versioned and not df.isCheckedOut()),
    )


def _require_versioned() -> None:
    if not session.domain_file.isVersioned():
        raise GhidraError(
            "This program is not under version control. Open it from a Ghidra Server "
            "with open_database(file_path='ghidra://host/repository/path').",
            error_type="NotVersioned",
        )


def _checkin_handler(comment: str, keep_checked_out: bool):
    from ghidra.framework.data import CheckinHandler  # noqa: PLC0415
    from jpype import JImplements, JOverride  # noqa: PLC0415

    @JImplements(CheckinHandler)
    class _Handler:
        @JOverride
        def getComment(self):
            return comment

        @JOverride
        def keepCheckedOut(self):
            return keep_checked_out

        @JOverride
        def createKeepFile(self):
            return False

    return _Handler()


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"versioning"})
    @session.require_open
    def get_version_state() -> VersionState:
        """Report the open program's version-control state.

        Use before editing a program opened from a Ghidra Server: it says whether
        it is checked out, whether save_database can succeed, and whether a newer
        version exists. Returns {path, versioned, checked_out, exclusive,
        modified_since_checkout, version, latest_version, can_save, read_only}.
        """
        return _state()

    @mcp.tool(annotations=ANNO_MUTATE, tags={"versioning"})
    @session.require_open
    def checkout_file(
        exclusive: Annotated[
            bool,
            Field(
                description=(
                    "Exclusive checkout: nobody else can check out until you check in. "
                    "Example: false"
                )
            ),
        ] = False,
    ) -> VersionState:
        """Check out the open versioned program so it can be changed and saved.

        Required before any edit of a program opened from a Ghidra Server: until
        then it is read-only. Re-opens the program on the checked-out copy, so
        call it before making changes. Returns the new version state.
        """
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        _require_versioned()
        df = session.domain_file
        if df.isCheckedOut():
            return _state()
        if not df.checkout(exclusive, TaskMonitor.DUMMY):
            raise GhidraError(
                "Checkout refused: someone holds an exclusive checkout (list_checkouts shows who).",
                error_type="CheckoutRefused",
            )
        session.reopen()
        return _state()

    @mcp.tool(annotations=ANNO_MUTATE, tags={"versioning"})
    @session.require_open
    def checkin_file(
        comment: Annotated[
            str,
            Field(description='Version comment. Example: "named packet handlers"'),
        ],
        keep_checked_out: Annotated[
            bool,
            Field(
                description=(
                    "Keep the checkout after checking in, to continue editing. Example: true"
                )
            ),
        ] = True,
    ) -> VersionState:
        """Publish the checked-out program's changes as a new server version.

        Saves pending changes first. Use when a coherent piece of work is done so
        others see it. Returns the new version state (version == latest_version).
        """
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        _require_versioned()
        df = session.domain_file
        if not df.isCheckedOut():
            raise GhidraError("Not checked out: checkout_file first.", error_type="NotCheckedOut")
        if session.program.isChanged():
            session.save(comment)
        if not df.modifiedSinceCheckout():
            return _state()
        df.checkin(_checkin_handler(comment, keep_checked_out), TaskMonitor.DUMMY)
        session.reopen()
        return _state()

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"versioning"})
    @session.require_open
    def undo_checkout() -> VersionState:
        """Discard the checkout and every change made since it.

        DESTRUCTIVE: unsaved and saved-but-not-checked-in work is lost. The
        program re-opens read-only at the latest server version. Returns the new
        version state.
        """
        _require_versioned()
        df = session.domain_file
        if not df.isCheckedOut():
            return _state()
        session.reopen(lambda: df.undoCheckout(False))
        return _state()

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"versioning"})
    @session.require_open
    def get_version_history() -> VersionHistory:
        """List every server version of the open program, oldest first.

        Returns {path, versions: [{version, user, comment, date}]}.
        """
        _require_versioned()
        df = session.domain_file
        return VersionHistory(
            path=str(df.getPathname()),
            versions=[
                VersionEntry(
                    version=int(v.getVersion()),
                    user=str(v.getUser()),
                    comment=str(v.getComment() or ""),
                    date=_iso(int(v.getCreateTime())),
                )
                for v in df.getVersionHistory()
            ],
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"versioning"})
    @session.require_open
    def list_checkouts() -> CheckoutList:
        """List who has the open program checked out (all users).

        Use when checkout_file is refused, or before an exclusive checkout.
        Returns {path, checkouts: [{checkout_id, user, version, exclusive, date,
        project}]}.
        """
        _require_versioned()
        df = session.domain_file
        return CheckoutList(
            path=str(df.getPathname()),
            checkouts=[
                CheckoutEntry(
                    checkout_id=int(c.getCheckoutId()),
                    user=str(c.getUser()),
                    version=int(c.getCheckoutVersion()),
                    exclusive=str(c.getCheckoutType()) == "EXCLUSIVE",
                    date=_iso(int(c.getCheckoutTime())),
                    project=str(c.getProjectPath() or ""),
                )
                for c in df.getCheckouts()
            ],
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"versioning"})
    @session.require_open
    def add_to_repository(
        repository: Annotated[
            str,
            Field(
                description=(
                    "Repository URL plus the folder to put the program in (folders are "
                    'created). Example: "ghidra://re-server/firmware/v2"'
                )
            ),
        ],
        comment: Annotated[
            str,
            Field(description='Version 1 comment. Example: "initial import, analyzed"'),
        ] = "initial import",
        name: Annotated[
            str,
            Field(
                description=(
                    "File name in the repository; empty keeps the program's name. "
                    'Example: "app_v2.bin"'
                )
            ),
        ] = "",
        keep_checked_out: Annotated[
            bool,
            Field(description="Keep a checkout of the new file. Example: false"),
        ] = False,
    ) -> AddedToRepository:
        """Put the open program, with its analysis and annotations, under version control.

        Use to share a binary you imported locally: it saves the program, copies
        the saved file into the repository folder and adds it as version 1. The
        open database stays the local copy; open the returned url with
        open_database to keep working on the shared one. Fails with
        AlreadyExists if the path is taken. Returns {url, version, checked_out}.
        """
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        from re_mcp_ghidra.server_projects import shared_project  # noqa: PLC0415
        from re_mcp_ghidra.server_url import parse_server_url  # noqa: PLC0415

        target = parse_server_url(repository, require_path=False)
        source = session.domain_file
        file_name = name or str(source.getName())
        if session.program.isChanged():
            session.save("before add_to_repository")

        project = shared_project(target)
        try:
            folder = project.getProjectData().getRootFolder()
            for part in [p for p in target.path.split("/") if p]:
                folder = folder.getFolder(part) or folder.createFolder(part)
            if folder.getFile(file_name) is not None:
                raise GhidraError(
                    f"{target.path.rstrip('/')}/{file_name} already exists in {target.repository}.",
                    error_type="AlreadyExists",
                )
            copied = source.copyTo(folder, TaskMonitor.DUMMY)
            if str(copied.getName()) != file_name:
                copied = copied.setName(file_name)
            copied.addToVersionControl(comment, keep_checked_out, TaskMonitor.DUMMY)
            path = str(copied.getPathname())
            return AddedToRepository(
                url=f"ghidra://{target.host}:{target.port}/{target.repository}{path}",
                version=int(copied.getLatestVersion()),
                checked_out=bool(copied.isCheckedOut()),
            )
        finally:
            project.close()
