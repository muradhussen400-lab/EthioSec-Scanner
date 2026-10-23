"""Initial schema matching SQLAlchemy models exactly

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-10-23 13:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users table
    op.create_table(
        'users',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('full_name', sa.String(), nullable=True),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('password_hash', sa.String(), nullable=False),
        sa.Column('role', sa.String(), nullable=True),
        sa.Column('website', sa.String(), nullable=True),
        sa.Column('is_verified', sa.Boolean(), nullable=False),
        sa.Column('verification_code_hash', sa.String(), nullable=True),
        sa.Column('verification_expires_at', sa.String(), nullable=True),
        sa.Column('verification_attempts', sa.Integer(), nullable=False),
        sa.Column('verification_sent_at', sa.String(), nullable=True),
        sa.Column('reset_token_hash', sa.String(), nullable=True),
        sa.Column('reset_expires_at', sa.String(), nullable=True),
        sa.Column('reset_attempts', sa.Integer(), nullable=False),
        sa.Column('session_revoked_at', sa.String(), nullable=True),
        sa.Column('failed_login_attempts', sa.Integer(), nullable=False),
        sa.Column('locked_until', sa.String(), nullable=True),
        sa.Column('created_at', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_full_name'), 'users', ['full_name'], unique=False)
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)

    # 2. scan_targets table
    op.create_table(
        'scan_targets',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=True),
        sa.Column('url', sa.String(), nullable=False),
        sa.Column('authorized', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.String(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_targets_id'), 'scan_targets', ['id'], unique=False)

    # 3. scans table
    op.create_table(
        'scans',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=True),
        sa.Column('target_url', sa.String(), nullable=False),
        sa.Column('depth', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=True),
        sa.Column('progress', sa.Integer(), nullable=True),
        sa.Column('stage', sa.String(), nullable=True),
        sa.Column('checks', sa.JSON(), nullable=True),
        sa.Column('modules', sa.JSON(), nullable=True),
        sa.Column('security_score', sa.Integer(), nullable=True),
        sa.Column('auth_context_1', sa.JSON(), nullable=True),
        sa.Column('auth_context_2', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.String(), nullable=True),
        sa.Column('finished_at', sa.String(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scans_id'), 'scans', ['id'], unique=False)

    # 4. findings table
    op.create_table(
        'findings',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('scan_id', sa.String(), nullable=True),
        sa.Column('target_id', sa.String(), nullable=True),
        sa.Column('type', sa.String(), nullable=False),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('confidence', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=True),
        sa.Column('url', sa.String(), nullable=True),
        sa.Column('parameter', sa.String(), nullable=True),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=True),
        sa.Column('http_method', sa.String(), nullable=True),
        sa.Column('request', sa.Text(), nullable=True),
        sa.Column('response_summary', sa.Text(), nullable=True),
        sa.Column('impact', sa.Text(), nullable=True),
        sa.Column('remediation', sa.JSON(), nullable=True),
        sa.Column('owasp', sa.String(), nullable=True),
        sa.Column('cwe', sa.String(), nullable=True),
        sa.Column('ai_explanation', sa.Text(), nullable=True),
        sa.Column('created_at', sa.String(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.ForeignKeyConstraint(['target_id'], ['scan_targets.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_findings_id'), 'findings', ['id'], unique=False)

    # 5. user_settings table
    op.create_table(
        'user_settings',
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('default_scan_depth', sa.String(), nullable=True),
        sa.Column('notif_scan_completed', sa.Boolean(), nullable=True),
        sa.Column('notif_scan_failed', sa.Boolean(), nullable=True),
        sa.Column('notif_security_findings', sa.Boolean(), nullable=True),
        sa.Column('updated_at', sa.String(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('user_id')
    )
    op.create_index(op.f('ix_user_settings_user_id'), 'user_settings', ['user_id'], unique=False)


def downgrade() -> None:
    # Drop in reverse dependency order
    op.drop_index(op.f('ix_user_settings_user_id'), table_name='user_settings')
    op.drop_table('user_settings')

    op.drop_index(op.f('ix_findings_id'), table_name='findings')
    op.drop_table('findings')

    op.drop_index(op.f('ix_scans_id'), table_name='scans')
    op.drop_table('scans')

    op.drop_index(op.f('ix_scan_targets_id'), table_name='scan_targets')
    op.drop_table('scan_targets')

    op.drop_index(op.f('ix_users_id'), table_name='users')
    op.drop_index(op.f('ix_users_full_name'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
