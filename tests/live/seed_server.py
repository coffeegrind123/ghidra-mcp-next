# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Create a repository on a test Ghidra Server and add one versioned program.

Run in its own process (it starts a JVM):
    python seed_server.py <port> <user> <password> <work dir> <binary>
"""

import os
import sys

import pyghidra


def main() -> None:
    port, user, password, work, binary = sys.argv[1:6]
    pyghidra.start(install_dir=os.environ["GHIDRA_INSTALL_DIR"])

    # Java packages exist only once the JVM has started.
    from ghidra.framework.client import ClientUtil, PasswordClientAuthenticator  # noqa: PLC0415
    from ghidra.framework.model import ProjectLocator  # noqa: PLC0415
    from ghidra.pyghidra import PyGhidraProjectManager  # noqa: PLC0415
    from java.io import File  # noqa: PLC0415

    ClientUtil.setClientAuthenticator(PasswordClientAuthenticator(user, password))
    server = ClientUtil.getRepositoryServer("127.0.0.1", int(port), True)
    repo = server.createRepository("testrepo")
    repo.connect()

    os.makedirs(work, exist_ok=True)
    project = PyGhidraProjectManager().createProject(ProjectLocator(work, "seed"), repo, False)
    project.getProjectData().getRootFolder().createFolder("bins")
    loader = pyghidra.program_loader().project(project).source(File(binary))
    with loader.projectFolderPath("/bins").name("sample").load() as results:
        results.save(pyghidra.task_monitor())
    sample = project.getProjectData().getFile("/bins/sample")
    sample.addToVersionControl("initial import", False, pyghidra.task_monitor())
    project.close()
    print("seeded")


if __name__ == "__main__":
    main()
