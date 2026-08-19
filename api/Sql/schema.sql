/* =============================================================================
   SystemAdminMonitoring  --  custom MSSQL schema for the Prometheus ingestion API.
   Mirrors the EF Core model (api/Data). Run this once against a fresh database as
   the production alternative to EnsureCreated (set Ingest:EnsureCreated=false).

   Layout:
     * CONFIG / TOPOLOGY tables  <- synced from systems_config.yml
     * SAMPLE tables             <- one set of rows per PollRun (the time series)
   Optional data (backups) lives in dedicated tables that simply stay empty for
   systems without a `backups:` block.
   ============================================================================= */

-- CREATE DATABASE SystemAdminMonitoring;
-- GO
-- USE SystemAdminMonitoring;
-- GO

/* ---------------------------------------------------------------- CONFIG ---- */

CREATE TABLE dbo.Systems (
    Id            INT IDENTITY(1,1) CONSTRAINT PK_Systems PRIMARY KEY,
    Name          NVARCHAR(128) NOT NULL,
    DisplayOrder  INT NOT NULL,
    CONSTRAINT UQ_Systems_Name UNIQUE (Name)
);

CREATE TABLE dbo.Hosts (
    Id         INT IDENTITY(1,1) CONSTRAINT PK_Hosts PRIMARY KEY,
    SystemId   INT NOT NULL,
    Role       NVARCHAR(64) NULL,
    Label      NVARCHAR(256) NOT NULL,
    Instance   NVARCHAR(128) NOT NULL,
    Os         NVARCHAR(16) NOT NULL,
    CONSTRAINT FK_Hosts_Systems FOREIGN KEY (SystemId) REFERENCES dbo.Systems(Id) ON DELETE CASCADE,
    CONSTRAINT UQ_Hosts_System_Instance UNIQUE (SystemId, Instance)
);
CREATE INDEX IX_Hosts_Instance ON dbo.Hosts(Instance);

CREATE TABLE dbo.ServiceChecks (
    Id         INT IDENTITY(1,1) CONSTRAINT PK_ServiceChecks PRIMARY KEY,
    SystemId   INT NOT NULL,
    Name       NVARCHAR(256) NOT NULL,
    Class      NVARCHAR(16) NOT NULL,
    CheckType  NVARCHAR(32) NOT NULL,
    Query      NVARCHAR(1024) NULL,
    NameLabel  NVARCHAR(128) NULL,
    Service    NVARCHAR(256) NULL,
    Unit       NVARCHAR(256) NULL,
    UnitType   NVARCHAR(64) NULL,
    Instance   NVARCHAR(128) NULL,
    Target     NVARCHAR(512) NULL,
    CONSTRAINT FK_ServiceChecks_Systems FOREIGN KEY (SystemId) REFERENCES dbo.Systems(Id) ON DELETE CASCADE,
    CONSTRAINT UQ_ServiceChecks_System_Name UNIQUE (SystemId, Name)
);

CREATE TABLE dbo.ServiceMembers (
    Id              INT IDENTITY(1,1) CONSTRAINT PK_ServiceMembers PRIMARY KEY,
    ServiceCheckId  INT NOT NULL,
    Name            NVARCHAR(256) NOT NULL,
    CONSTRAINT FK_ServiceMembers_ServiceChecks FOREIGN KEY (ServiceCheckId) REFERENCES dbo.ServiceChecks(Id) ON DELETE CASCADE
);

CREATE TABLE dbo.LinkChecks (
    Id        INT IDENTITY(1,1) CONSTRAINT PK_LinkChecks PRIMARY KEY,
    SystemId  INT NULL,
    Url       NVARCHAR(512) NOT NULL,
    CONSTRAINT FK_LinkChecks_Systems FOREIGN KEY (SystemId) REFERENCES dbo.Systems(Id) ON DELETE SET NULL
);
CREATE INDEX IX_LinkChecks_Url ON dbo.LinkChecks(Url);

CREATE TABLE dbo.ReadingConfigs (
    Id        INT IDENTITY(1,1) CONSTRAINT PK_ReadingConfigs PRIMARY KEY,
    SystemId  INT NOT NULL,
    [Key]     NVARCHAR(32) NOT NULL,
    Expr      NVARCHAR(256) NOT NULL,
    CONSTRAINT FK_ReadingConfigs_Systems FOREIGN KEY (SystemId) REFERENCES dbo.Systems(Id) ON DELETE CASCADE,
    CONSTRAINT UQ_ReadingConfigs_System_Key UNIQUE (SystemId, [Key])
);

-- OPTIONAL: at most one row per system; systems without backups have NONE.
CREATE TABLE dbo.BackupConfigs (
    Id          INT IDENTITY(1,1) CONSTRAINT PK_BackupConfigs PRIMARY KEY,
    SystemId    INT NOT NULL,
    Instance    NVARCHAR(128) NOT NULL,
    Tracks      NVARCHAR(256) NULL,
    MaxAgeDays  INT NULL,   -- NULL = daily default (today/yesterday); set for a slower-than-daily backup cycle
    CONSTRAINT FK_BackupConfigs_Systems FOREIGN KEY (SystemId) REFERENCES dbo.Systems(Id) ON DELETE CASCADE,
    CONSTRAINT UQ_BackupConfigs_System UNIQUE (SystemId)
);

/* ---------------------------------------------------------------- SAMPLES --- */

CREATE TABLE dbo.PollRuns (
    Id                  BIGINT IDENTITY(1,1) CONSTRAINT PK_PollRuns PRIMARY KEY,
    StartedAt           DATETIME2 NOT NULL,
    CompletedAt         DATETIME2 NULL,
    PromUrl             NVARCHAR(256) NOT NULL,
    Status              NVARCHAR(16) NOT NULL,       -- Running | Succeeded | Failed
    Error               NVARCHAR(2048) NULL,
    SystemsPolled       INT NOT NULL DEFAULT 0,
    SamplesWritten      INT NOT NULL DEFAULT 0,
    AttentionImmediate  INT NOT NULL DEFAULT 0,
    AttentionWatch      INT NOT NULL DEFAULT 0
);
CREATE INDEX IX_PollRuns_StartedAt ON dbo.PollRuns(StartedAt);

CREATE TABLE dbo.DiskSamples (
    Id          BIGINT IDENTITY(1,1) CONSTRAINT PK_DiskSamples PRIMARY KEY,
    PollRunId   BIGINT NOT NULL,
    HostId      INT NOT NULL,
    Mountpoint  NVARCHAR(256) NOT NULL,
    UsedPct     FLOAT NULL,
    FreeGb      FLOAT NULL,
    SizeGb      FLOAT NULL,
    CONSTRAINT FK_DiskSamples_PollRuns FOREIGN KEY (PollRunId) REFERENCES dbo.PollRuns(Id) ON DELETE CASCADE,
    CONSTRAINT FK_DiskSamples_Hosts    FOREIGN KEY (HostId)    REFERENCES dbo.Hosts(Id)    ON DELETE NO ACTION
);
CREATE INDEX IX_DiskSamples_PollRun ON dbo.DiskSamples(PollRunId);
CREATE INDEX IX_DiskSamples_Host_PollRun ON dbo.DiskSamples(HostId, PollRunId);

CREATE TABLE dbo.MemorySamples (
    Id         BIGINT IDENTITY(1,1) CONSTRAINT PK_MemorySamples PRIMARY KEY,
    PollRunId  BIGINT NOT NULL,
    HostId     INT NOT NULL,
    UsedPct    FLOAT NOT NULL,
    CONSTRAINT FK_MemorySamples_PollRuns FOREIGN KEY (PollRunId) REFERENCES dbo.PollRuns(Id) ON DELETE CASCADE,
    CONSTRAINT FK_MemorySamples_Hosts    FOREIGN KEY (HostId)    REFERENCES dbo.Hosts(Id)    ON DELETE NO ACTION
);
CREATE INDEX IX_MemorySamples_PollRun ON dbo.MemorySamples(PollRunId);
CREATE INDEX IX_MemorySamples_Host_PollRun ON dbo.MemorySamples(HostId, PollRunId);

CREATE TABLE dbo.CpuSamples (
    Id         BIGINT IDENTITY(1,1) CONSTRAINT PK_CpuSamples PRIMARY KEY,
    PollRunId  BIGINT NOT NULL,
    HostId     INT NOT NULL,
    UsedPct    FLOAT NOT NULL,                 -- CPU busy % (100 - idle, 5-min avg)
    CONSTRAINT FK_CpuSamples_PollRuns FOREIGN KEY (PollRunId) REFERENCES dbo.PollRuns(Id) ON DELETE CASCADE,
    CONSTRAINT FK_CpuSamples_Hosts    FOREIGN KEY (HostId)    REFERENCES dbo.Hosts(Id)    ON DELETE NO ACTION
);
CREATE INDEX IX_CpuSamples_PollRun ON dbo.CpuSamples(PollRunId);
CREATE INDEX IX_CpuSamples_Host_PollRun ON dbo.CpuSamples(HostId, PollRunId);

CREATE TABLE dbo.HostReachabilitySamples (
    Id         BIGINT IDENTITY(1,1) CONSTRAINT PK_HostReachabilitySamples PRIMARY KEY,
    PollRunId  BIGINT NOT NULL,
    HostId     INT NOT NULL,
    IsUp       BIT NOT NULL,
    CONSTRAINT FK_Reach_PollRuns FOREIGN KEY (PollRunId) REFERENCES dbo.PollRuns(Id) ON DELETE CASCADE,
    CONSTRAINT FK_Reach_Hosts    FOREIGN KEY (HostId)    REFERENCES dbo.Hosts(Id)    ON DELETE NO ACTION
);
CREATE INDEX IX_Reach_PollRun ON dbo.HostReachabilitySamples(PollRunId);
CREATE INDEX IX_Reach_Host_PollRun ON dbo.HostReachabilitySamples(HostId, PollRunId);

CREATE TABLE dbo.ServiceStatusSamples (
    Id              BIGINT IDENTITY(1,1) CONSTRAINT PK_ServiceStatusSamples PRIMARY KEY,
    PollRunId       BIGINT NOT NULL,
    ServiceCheckId  INT NOT NULL,
    MemberName      NVARCHAR(256) NOT NULL,
    IsUp            BIT NOT NULL,
    CONSTRAINT FK_SvcStatus_PollRuns      FOREIGN KEY (PollRunId)      REFERENCES dbo.PollRuns(Id)      ON DELETE CASCADE,
    CONSTRAINT FK_SvcStatus_ServiceChecks FOREIGN KEY (ServiceCheckId) REFERENCES dbo.ServiceChecks(Id) ON DELETE NO ACTION
);
CREATE INDEX IX_SvcStatus_PollRun ON dbo.ServiceStatusSamples(PollRunId);
CREATE INDEX IX_SvcStatus_Check_PollRun ON dbo.ServiceStatusSamples(ServiceCheckId, PollRunId);

CREATE TABLE dbo.LinkProbeSamples (
    Id               BIGINT IDENTITY(1,1) CONSTRAINT PK_LinkProbeSamples PRIMARY KEY,
    PollRunId        BIGINT NOT NULL,
    LinkCheckId      INT NOT NULL,
    IsUp             BIT NOT NULL,
    HttpCode         INT NULL,
    Ssl              BIT NULL,
    CertDays         FLOAT NULL,
    TlsVersion       NVARCHAR(32) NULL,
    DurationSeconds  FLOAT NULL,
    CONSTRAINT FK_LinkProbe_PollRuns   FOREIGN KEY (PollRunId)   REFERENCES dbo.PollRuns(Id)   ON DELETE CASCADE,
    CONSTRAINT FK_LinkProbe_LinkChecks FOREIGN KEY (LinkCheckId) REFERENCES dbo.LinkChecks(Id) ON DELETE NO ACTION
);
CREATE INDEX IX_LinkProbe_PollRun ON dbo.LinkProbeSamples(PollRunId);
CREATE INDEX IX_LinkProbe_Link_PollRun ON dbo.LinkProbeSamples(LinkCheckId, PollRunId);

-- OPTIONAL data: rows written ONLY for systems that have a BackupConfig.
CREATE TABLE dbo.BackupFileSamples (
    Id              BIGINT IDENTITY(1,1) CONSTRAINT PK_BackupFileSamples PRIMARY KEY,
    PollRunId       BIGINT NOT NULL,
    BackupConfigId  INT NOT NULL,
    FileName        NVARCHAR(512) NOT NULL,
    Day             NVARCHAR(32) NULL,
    MtimeUnix       FLOAT NOT NULL,
    IsFresh         BIT NOT NULL,
    CONSTRAINT FK_BackupFile_PollRuns      FOREIGN KEY (PollRunId)      REFERENCES dbo.PollRuns(Id)      ON DELETE CASCADE,
    CONSTRAINT FK_BackupFile_BackupConfigs FOREIGN KEY (BackupConfigId) REFERENCES dbo.BackupConfigs(Id) ON DELETE NO ACTION
);
CREATE INDEX IX_BackupFile_PollRun ON dbo.BackupFileSamples(PollRunId);
CREATE INDEX IX_BackupFile_Config_PollRun ON dbo.BackupFileSamples(BackupConfigId, PollRunId);

CREATE TABLE dbo.BackupCheckSamples (
    Id                  BIGINT IDENTITY(1,1) CONSTRAINT PK_BackupCheckSamples PRIMARY KEY,
    PollRunId           BIGINT NOT NULL,
    BackupConfigId      INT NOT NULL,
    FileCount           INT NULL,
    Success             BIT NULL,
    CheckTimestampUnix  FLOAT NULL,
    AnyFresh            BIT NOT NULL,
    CONSTRAINT FK_BackupCheck_PollRuns      FOREIGN KEY (PollRunId)      REFERENCES dbo.PollRuns(Id)      ON DELETE CASCADE,
    CONSTRAINT FK_BackupCheck_BackupConfigs FOREIGN KEY (BackupConfigId) REFERENCES dbo.BackupConfigs(Id) ON DELETE NO ACTION
);
CREATE INDEX IX_BackupCheck_PollRun ON dbo.BackupCheckSamples(PollRunId);
CREATE INDEX IX_BackupCheck_Config_PollRun ON dbo.BackupCheckSamples(BackupConfigId, PollRunId);

CREATE TABLE dbo.ReadingSamples (
    Id         BIGINT IDENTITY(1,1) CONSTRAINT PK_ReadingSamples PRIMARY KEY,
    PollRunId  BIGINT NOT NULL,
    SystemId   INT NOT NULL,
    [Key]      NVARCHAR(32) NOT NULL,
    Value      FLOAT NULL,
    CONSTRAINT FK_Reading_PollRuns FOREIGN KEY (PollRunId) REFERENCES dbo.PollRuns(Id)  ON DELETE CASCADE,
    CONSTRAINT FK_Reading_Systems  FOREIGN KEY (SystemId)  REFERENCES dbo.Systems(Id)   ON DELETE NO ACTION
);
CREATE INDEX IX_Reading_PollRun ON dbo.ReadingSamples(PollRunId);
CREATE INDEX IX_Reading_System_Key_PollRun ON dbo.ReadingSamples(SystemId, [Key], PollRunId);

CREATE TABLE dbo.AttentionItems (
    Id          BIGINT IDENTITY(1,1) CONSTRAINT PK_AttentionItems PRIMARY KEY,
    PollRunId   BIGINT NOT NULL,
    Severity    NVARCHAR(16) NOT NULL,   -- Immediate | Watch
    Category    NVARCHAR(32) NOT NULL,   -- MissingBackup|Unreachable|ServiceDown|DiskNearFull|HighDisk|HighRam|HighCpu|SslExpiry|LinkDown|UntrackedBackup
    SystemName  NVARCHAR(128) NOT NULL,
    HostLabel   NVARCHAR(256) NULL,
    Detail      NVARCHAR(512) NOT NULL,
    CONSTRAINT FK_Attention_PollRuns FOREIGN KEY (PollRunId) REFERENCES dbo.PollRuns(Id) ON DELETE CASCADE
);
CREATE INDEX IX_Attention_PollRun ON dbo.AttentionItems(PollRunId);
CREATE INDEX IX_Attention_PollRun_Severity ON dbo.AttentionItems(PollRunId, Severity);
GO
