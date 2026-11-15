IF OBJECT_ID(N'[__EFMigrationsHistory]') IS NULL
BEGIN
    CREATE TABLE [__EFMigrationsHistory] (
        [MigrationId] nvarchar(150) NOT NULL,
        [ProductVersion] nvarchar(32) NOT NULL,
        CONSTRAINT [PK___EFMigrationsHistory] PRIMARY KEY ([MigrationId])
    );
END;
GO

BEGIN TRANSACTION;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE TABLE [ConfigurationChanges] (
        [Id] bigint NOT NULL IDENTITY,
        [EntityType] nvarchar(50) NOT NULL,
        [EntityId] uniqueidentifier NOT NULL,
        [EntityKey] nvarchar(200) NOT NULL,
        [Action] nvarchar(20) NOT NULL,
        [ChangedBy] nvarchar(200) NOT NULL,
        [ChangedAtUtc] datetime2 NOT NULL,
        [CorrelationId] nvarchar(64) NOT NULL,
        [ChangesJson] nvarchar(max) NOT NULL,
        CONSTRAINT [PK_ConfigurationChanges] PRIMARY KEY ([Id])
    );
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE TABLE [Destinations] (
        [Id] uniqueidentifier NOT NULL,
        [Key] nvarchar(100) NOT NULL,
        [Name] nvarchar(200) NOT NULL,
        [BaseUrl] nvarchar(2000) NOT NULL,
        [IsEnabled] bit NOT NULL,
        [TimeoutSeconds] int NOT NULL,
        [AllowedPorts] nvarchar(200) NULL,
        [AuthType] nvarchar(30) NOT NULL,
        [AuthHeaderName] nvarchar(100) NULL,
        [AuthSecretReference] nvarchar(300) NULL,
        [CreatedAtUtc] datetime2 NOT NULL,
        [UpdatedAtUtc] datetime2 NOT NULL,
        [ConcurrencyStamp] nvarchar(64) NOT NULL,
        CONSTRAINT [PK_Destinations] PRIMARY KEY ([Id])
    );
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE TABLE [EncryptionProfiles] (
        [Id] uniqueidentifier NOT NULL,
        [Key] nvarchar(100) NOT NULL,
        [Algorithm] nvarchar(30) NOT NULL,
        [KeyReference] nvarchar(300) NOT NULL,
        [KeyVersion] int NOT NULL,
        [IsEnabled] bit NOT NULL,
        [CreatedAtUtc] datetime2 NOT NULL,
        [UpdatedAtUtc] datetime2 NOT NULL,
        [ConcurrencyStamp] nvarchar(64) NOT NULL,
        CONSTRAINT [PK_EncryptionProfiles] PRIMARY KEY ([Id])
    );
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE TABLE [RequestLogs] (
        [Id] bigint NOT NULL IDENTITY,
        [CorrelationId] nvarchar(64) NOT NULL,
        [OperationKey] nvarchar(200) NULL,
        [OperationId] uniqueidentifier NULL,
        [DestinationId] uniqueidentifier NULL,
        [DestinationKey] nvarchar(100) NULL,
        [HttpMethod] nvarchar(10) NULL,
        [StartedAtUtc] datetime2 NOT NULL,
        [CompletedAtUtc] datetime2 NULL,
        [DurationMs] bigint NULL,
        [Forwarded] bit NOT NULL,
        [UpstreamStatusCode] int NULL,
        [ProxyStatusCode] int NOT NULL,
        [Outcome] nvarchar(30) NOT NULL,
        [ReasonCode] nvarchar(100) NULL,
        [ReasonDetail] nvarchar(500) NULL,
        [ClientAddress] nvarchar(64) NULL,
        [RequestBytes] bigint NULL,
        [ResponseBytes] bigint NULL,
        CONSTRAINT [PK_RequestLogs] PRIMARY KEY ([Id])
    );
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE TABLE [Operations] (
        [Id] uniqueidentifier NOT NULL,
        [Key] nvarchar(200) NOT NULL,
        [DestinationId] uniqueidentifier NOT NULL,
        [HttpMethod] nvarchar(10) NOT NULL,
        [PathTemplate] nvarchar(2000) NOT NULL,
        [IsEnabled] bit NOT NULL,
        [MaxRequestBytes] bigint NOT NULL,
        [MaxResponseBytes] bigint NULL,
        [TimeoutSeconds] int NULL,
        [RequiresEncryption] bit NOT NULL,
        [EncryptionProfileId] uniqueidentifier NULL,
        [AllowUnknownParameters] bit NOT NULL,
        [SupportsIdempotencyKey] bit NOT NULL,
        [CreatedAtUtc] datetime2 NOT NULL,
        [UpdatedAtUtc] datetime2 NOT NULL,
        [ConcurrencyStamp] nvarchar(64) NOT NULL,
        CONSTRAINT [PK_Operations] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_Operations_Destinations_DestinationId] FOREIGN KEY ([DestinationId]) REFERENCES [Destinations] ([Id]) ON DELETE NO ACTION,
        CONSTRAINT [FK_Operations_EncryptionProfiles_EncryptionProfileId] FOREIGN KEY ([EncryptionProfileId]) REFERENCES [EncryptionProfiles] ([Id]) ON DELETE NO ACTION
    );
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE TABLE [HeaderRules] (
        [Id] uniqueidentifier NOT NULL,
        [OperationId] uniqueidentifier NOT NULL,
        [HeaderName] nvarchar(100) NOT NULL,
        [Direction] nvarchar(10) NOT NULL,
        CONSTRAINT [PK_HeaderRules] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_HeaderRules_Operations_OperationId] FOREIGN KEY ([OperationId]) REFERENCES [Operations] ([Id]) ON DELETE CASCADE
    );
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE TABLE [ParameterRules] (
        [Id] uniqueidentifier NOT NULL,
        [OperationId] uniqueidentifier NOT NULL,
        [Name] nvarchar(100) NOT NULL,
        [Location] nvarchar(10) NOT NULL,
        [IsRequired] bit NOT NULL,
        [DataType] nvarchar(20) NOT NULL,
        [MaxLength] int NULL,
        [MinValue] decimal(28,8) NULL,
        [MaxValue] decimal(28,8) NULL,
        [Pattern] nvarchar(500) NULL,
        [AllowedValues] nvarchar(2000) NULL,
        CONSTRAINT [PK_ParameterRules] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_ParameterRules_Operations_OperationId] FOREIGN KEY ([OperationId]) REFERENCES [Operations] ([Id]) ON DELETE CASCADE
    );
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_ConfigurationChanges_EntityType_EntityId_ChangedAtUtc] ON [ConfigurationChanges] ([EntityType], [EntityId], [ChangedAtUtc]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_Destinations_Key] ON [Destinations] ([Key]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_EncryptionProfiles_Key] ON [EncryptionProfiles] ([Key]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_HeaderRules_OperationId_HeaderName_Direction] ON [HeaderRules] ([OperationId], [HeaderName], [Direction]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_Operations_DestinationId] ON [Operations] ([DestinationId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_Operations_EncryptionProfileId] ON [Operations] ([EncryptionProfileId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_Operations_Key] ON [Operations] ([Key]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_ParameterRules_OperationId_Name] ON [ParameterRules] ([OperationId], [Name]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_RequestLogs_CorrelationId] ON [RequestLogs] ([CorrelationId]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_RequestLogs_OperationKey_StartedAtUtc] ON [RequestLogs] ([OperationKey], [StartedAtUtc]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_RequestLogs_StartedAtUtc] ON [RequestLogs] ([StartedAtUtc]);
END;
GO

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20261108181619_InitialCreate'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20261108181619_InitialCreate', N'8.0.19');
END;
GO

COMMIT;
GO

