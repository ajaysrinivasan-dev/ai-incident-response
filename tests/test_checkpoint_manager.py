import checkpoint_manager


def test_investigation_metadata_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setattr(
        checkpoint_manager,
        "CHECKPOINT_DB",
        tmp_path / "metadata.db",
    )

    assert checkpoint_manager.create_investigation(
        thread_id="thread-1",
        title="Test Investigation",
        scenario="Custom Incident",
        severity="high",
    )

    investigation = checkpoint_manager.get_investigation("thread-1")

    assert investigation is not None
    assert investigation["status"] == "Running"
    assert investigation["severity"] == "high"

    assert checkpoint_manager.update_investigation(
        "thread-1",
        status="Completed",
        severity="critical",
    )

    updated = checkpoint_manager.get_investigation("thread-1")

    assert updated is not None
    assert updated["status"] == "Completed"
    assert updated["severity"] == "critical"

    assert checkpoint_manager.archive_investigation("thread-1")
    archived = checkpoint_manager.get_investigation("thread-1")

    assert archived is not None
    assert archived["status"] == "Archived"

    assert checkpoint_manager.delete_investigation("thread-1")
    assert checkpoint_manager.get_investigation("thread-1") is None
