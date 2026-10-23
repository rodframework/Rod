using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Rod.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class UnifiedEntityModelLinks : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // The recipient rows' own engagement and operator attribution
            // (Sec 15.4): added nullable, backfilled off the campaign head,
            // then tightened -- an additive not-null default would stamp
            // every existing row with the empty Guid instead.
            migrationBuilder.AddColumn<Guid>(
                name: "created_by",
                table: "campaign_recipients",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "engagement_id",
                table: "campaign_recipients",
                type: "uuid",
                nullable: true);

            migrationBuilder.Sql("""
                UPDATE campaign_recipients AS r
                SET engagement_id = c.engagement_id,
                    created_by = c.created_by
                FROM campaigns AS c
                WHERE r.campaign_id = c.campaign_id
                  AND r.engagement_id IS NULL
                """);

            migrationBuilder.AlterColumn<Guid>(
                name: "created_by",
                table: "campaign_recipients",
                type: "uuid",
                nullable: false,
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldNullable: true);

            migrationBuilder.AlterColumn<Guid>(
                name: "engagement_id",
                table: "campaign_recipients",
                type: "uuid",
                nullable: false,
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldNullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "recon_asset_id",
                table: "campaign_recipients",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddUniqueConstraint(
                name: "ux_implants_id_engagement_id",
                table: "implants",
                columns: new[] { "implant_id", "engagement_id" });

            migrationBuilder.AddUniqueConstraint(
                name: "ux_campaigns_id_engagement_id",
                table: "campaigns",
                columns: new[] { "campaign_id", "engagement_id" });

            migrationBuilder.AddUniqueConstraint(
                name: "ux_campaign_recipients_id_engagement_id",
                table: "campaign_recipients",
                columns: new[] { "campaign_recipient_id", "engagement_id" });

            migrationBuilder.CreateTable(
                name: "recon_assets",
                columns: table => new
                {
                    recon_asset_id = table.Column<Guid>(type: "uuid", nullable: false),
                    engagement_id = table.Column<Guid>(type: "uuid", nullable: false),
                    kind = table.Column<int>(type: "integer", nullable: false),
                    value = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: false),
                    display_name = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: true),
                    source_artifact_id = table.Column<Guid>(type: "uuid", nullable: true),
                    created_by = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_recon_assets", x => x.recon_asset_id);
                    table.UniqueConstraint("ux_recon_assets_id_engagement_id", x => new { x.recon_asset_id, x.engagement_id });
                });

            migrationBuilder.CreateIndex(
                name: "IX_implants_campaign_id_engagement_id",
                table: "implants",
                columns: new[] { "campaign_id", "engagement_id" });

            migrationBuilder.CreateIndex(
                name: "IX_implants_campaign_recipient_id_engagement_id",
                table: "implants",
                columns: new[] { "campaign_recipient_id", "engagement_id" });

            migrationBuilder.CreateIndex(
                name: "ix_implants_parent_implant_id_engagement_id",
                table: "implants",
                columns: new[] { "parent_implant_id", "engagement_id" },
                filter: "parent_implant_id IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_campaign_recipients_enrolled_implant_id_engagement_id",
                table: "campaign_recipients",
                columns: new[] { "enrolled_implant_id", "engagement_id" });

            migrationBuilder.CreateIndex(
                name: "ix_campaign_recipients_recon_asset_id_engagement_id",
                table: "campaign_recipients",
                columns: new[] { "recon_asset_id", "engagement_id" },
                filter: "recon_asset_id IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_recon_assets_engagement_id",
                table: "recon_assets",
                column: "engagement_id");

            migrationBuilder.CreateIndex(
                name: "ux_recon_assets_engagement_id_kind_value",
                table: "recon_assets",
                columns: new[] { "engagement_id", "kind", "value" },
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "fk_recipients_enrolled_implant",
                table: "campaign_recipients",
                columns: new[] { "enrolled_implant_id", "engagement_id" },
                principalTable: "implants",
                principalColumns: new[] { "implant_id", "engagement_id" },
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_recipients_recon_asset",
                table: "campaign_recipients",
                columns: new[] { "recon_asset_id", "engagement_id" },
                principalTable: "recon_assets",
                principalColumns: new[] { "recon_asset_id", "engagement_id" },
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_implants_campaign",
                table: "implants",
                columns: new[] { "campaign_id", "engagement_id" },
                principalTable: "campaigns",
                principalColumns: new[] { "campaign_id", "engagement_id" },
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_implants_campaign_recipient",
                table: "implants",
                columns: new[] { "campaign_recipient_id", "engagement_id" },
                principalTable: "campaign_recipients",
                principalColumns: new[] { "campaign_recipient_id", "engagement_id" },
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "fk_implants_parent",
                table: "implants",
                columns: new[] { "parent_implant_id", "engagement_id" },
                principalTable: "implants",
                principalColumns: new[] { "implant_id", "engagement_id" },
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "fk_recipients_enrolled_implant",
                table: "campaign_recipients");

            migrationBuilder.DropForeignKey(
                name: "fk_recipients_recon_asset",
                table: "campaign_recipients");

            migrationBuilder.DropForeignKey(
                name: "fk_implants_campaign",
                table: "implants");

            migrationBuilder.DropForeignKey(
                name: "fk_implants_campaign_recipient",
                table: "implants");

            migrationBuilder.DropForeignKey(
                name: "fk_implants_parent",
                table: "implants");

            migrationBuilder.DropTable(
                name: "recon_assets");

            migrationBuilder.DropUniqueConstraint(
                name: "ux_implants_id_engagement_id",
                table: "implants");

            migrationBuilder.DropIndex(
                name: "IX_implants_campaign_id_engagement_id",
                table: "implants");

            migrationBuilder.DropIndex(
                name: "IX_implants_campaign_recipient_id_engagement_id",
                table: "implants");

            migrationBuilder.DropIndex(
                name: "ix_implants_parent_implant_id_engagement_id",
                table: "implants");

            migrationBuilder.DropUniqueConstraint(
                name: "ux_campaigns_id_engagement_id",
                table: "campaigns");

            migrationBuilder.DropUniqueConstraint(
                name: "ux_campaign_recipients_id_engagement_id",
                table: "campaign_recipients");

            migrationBuilder.DropIndex(
                name: "IX_campaign_recipients_enrolled_implant_id_engagement_id",
                table: "campaign_recipients");

            migrationBuilder.DropIndex(
                name: "ix_campaign_recipients_recon_asset_id_engagement_id",
                table: "campaign_recipients");

            migrationBuilder.DropColumn(
                name: "created_by",
                table: "campaign_recipients");

            migrationBuilder.DropColumn(
                name: "engagement_id",
                table: "campaign_recipients");

            migrationBuilder.DropColumn(
                name: "recon_asset_id",
                table: "campaign_recipients");
        }
    }
}
