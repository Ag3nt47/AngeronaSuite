# Interface control reference

This source index lists declared buttons, actions, checkboxes, radio buttons, tabs and menus in every GUI source file. Generated labels and context-dependent controls are identified by their declaration and handler instead of guessing their current contents. Shared builders can create several runtime controls from one declaration.

Declared control sites: **735**.

The linked source gives the exact handler. The master manual explains supported workflows and authority; a visible control does not imply that a provider is configured or that an action is authorized.

## Adaptation workbench

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| AUTO ADAPT… | QPushButton | `AdaptationWorkbench.__init__` | `self._show_auto_adapt` · [src/angerona/gui/adaptation_workbench.py:374](../../src/angerona/gui/adaptation_workbench.py#L374) |
| Overview | Tab | `AdaptationWorkbench.__init__` | [src/angerona/gui/adaptation_workbench.py:411](../../src/angerona/gui/adaptation_workbench.py#L411) |
| Audit + Drift | Tab | `AdaptationWorkbench.__init__` | [src/angerona/gui/adaptation_workbench.py:412](../../src/angerona/gui/adaptation_workbench.py#L412) |
| Exceptions + Feedback | Tab | `AdaptationWorkbench.__init__` | [src/angerona/gui/adaptation_workbench.py:413](../../src/angerona/gui/adaptation_workbench.py#L413) |
| Adapt Host | Tab | `AdaptationWorkbench.__init__` | [src/angerona/gui/adaptation_workbench.py:414](../../src/angerona/gui/adaptation_workbench.py#L414) |
| Sandbox | Tab | `AdaptationWorkbench.__init__` | [src/angerona/gui/adaptation_workbench.py:415](../../src/angerona/gui/adaptation_workbench.py#L415) |
| Automation | Tab | `AdaptationWorkbench.__init__` | [src/angerona/gui/adaptation_workbench.py:416](../../src/angerona/gui/adaptation_workbench.py#L416) |
| Activity | Tab | `AdaptationWorkbench.__init__` | [src/angerona/gui/adaptation_workbench.py:417](../../src/angerona/gui/adaptation_workbench.py#L417) |
| Independent Recovery | Tab | `AdaptationWorkbench.__init__` | [src/angerona/gui/adaptation_workbench.py:422](../../src/angerona/gui/adaptation_workbench.py#L422) |
| Windows Prevention | Tab | `AdaptationWorkbench.__init__` | [src/angerona/gui/adaptation_workbench.py:425](../../src/angerona/gui/adaptation_workbench.py#L425) |
| Close | QPushButton | `AdaptationWorkbench.__init__` | `self.close` · [src/angerona/gui/adaptation_workbench.py:434](../../src/angerona/gui/adaptation_workbench.py#L434) |
| Generated label or icon | QAction | `AdaptationWorkbench._action` | `slot` · [src/angerona/gui/adaptation_workbench.py:448](../../src/angerona/gui/adaptation_workbench.py#L448) |
| File | Menu | `AdaptationWorkbench._build_menu` | [src/angerona/gui/adaptation_workbench.py:454](../../src/angerona/gui/adaptation_workbench.py#L454) |
| Audit | Menu | `AdaptationWorkbench._build_menu` | [src/angerona/gui/adaptation_workbench.py:460](../../src/angerona/gui/adaptation_workbench.py#L460) |
| Adapt | Menu | `AdaptationWorkbench._build_menu` | [src/angerona/gui/adaptation_workbench.py:465](../../src/angerona/gui/adaptation_workbench.py#L465) |
| Safety | Menu | `AdaptationWorkbench._build_menu` | [src/angerona/gui/adaptation_workbench.py:474](../../src/angerona/gui/adaptation_workbench.py#L474) |
| Help | Menu | `AdaptationWorkbench._build_menu` | [src/angerona/gui/adaptation_workbench.py:480](../../src/angerona/gui/adaptation_workbench.py#L480) |
| Ask to apply | QCheckBox | `AdaptationWorkbench._show_auto_adapt` | [src/angerona/gui/adaptation_workbench.py:522](../../src/angerona/gui/adaptation_workbench.py#L522) |
| Enroll baseline | QCheckBox | `AdaptationWorkbench._show_auto_adapt` | [src/angerona/gui/adaptation_workbench.py:530](../../src/angerona/gui/adaptation_workbench.py#L530) |
| Cancel | QPushButton | `AdaptationWorkbench._show_auto_adapt` | `dialog.reject` · [src/angerona/gui/adaptation_workbench.py:555](../../src/angerona/gui/adaptation_workbench.py#L555) |
| Prepare automatically | QPushButton | `AdaptationWorkbench._show_auto_adapt` | `dialog.accept` · [src/angerona/gui/adaptation_workbench.py:557](../../src/angerona/gui/adaptation_workbench.py#L557) |
| Choose an adaptation profile… | QPushButton | `AdaptationWorkbench._build_overview_tab` | `self._show_adapt_host` · [src/angerona/gui/adaptation_workbench.py:627](../../src/angerona/gui/adaptation_workbench.py#L627) |
| AUTO ADAPT… | QPushButton | `AdaptationWorkbench._build_overview_tab` | `self._show_auto_adapt` · [src/angerona/gui/adaptation_workbench.py:630](../../src/angerona/gui/adaptation_workbench.py#L630) |
| Run safe automatic checkup | QPushButton | `AdaptationWorkbench._build_overview_tab` | `self._run_safe_checkup` · [src/angerona/gui/adaptation_workbench.py:633](../../src/angerona/gui/adaptation_workbench.py#L633) |
| Copy details | QPushButton | `AdaptationWorkbench._show_table_detail` | `lambda: QApplication.clipboard().setText(body.toPlainText())` · [src/angerona/gui/adaptation_workbench.py:755](../../src/angerona/gui/adaptation_workbench.py#L755) |
| Close | QPushButton | `AdaptationWorkbench._show_table_detail` | `dialog.close` · [src/angerona/gui/adaptation_workbench.py:759](../../src/angerona/gui/adaptation_workbench.py#L759) |
| Run deep audit | QPushButton | `AdaptationWorkbench._build_audit_tab` | `self._run_audit` · [src/angerona/gui/adaptation_workbench.py:778](../../src/angerona/gui/adaptation_workbench.py#L778) |
| Save as golden baseline… | QPushButton | `AdaptationWorkbench._build_audit_tab` | `self._save_baseline` · [src/angerona/gui/adaptation_workbench.py:781](../../src/angerona/gui/adaptation_workbench.py#L781) |
| Export JSON… | QPushButton | `AdaptationWorkbench._build_audit_tab` | `self._export_json` · [src/angerona/gui/adaptation_workbench.py:783](../../src/angerona/gui/adaptation_workbench.py#L783) |
| Export CSV… | QPushButton | `AdaptationWorkbench._build_audit_tab` | `self._export_csv` · [src/angerona/gui/adaptation_workbench.py:785](../../src/angerona/gui/adaptation_workbench.py#L785) |
| Pin selected as known-good exception… | QPushButton | `AdaptationWorkbench._build_audit_tab` | `self._pin_exception` · [src/angerona/gui/adaptation_workbench.py:797](../../src/angerona/gui/adaptation_workbench.py#L797) |
| Dismiss false positive + tune score… | QPushButton | `AdaptationWorkbench._build_audit_tab` | `self._dismiss_feedback` · [src/angerona/gui/adaptation_workbench.py:799](../../src/angerona/gui/adaptation_workbench.py#L799) |
| Refresh exceptions | QPushButton | `AdaptationWorkbench._build_exceptions_tab` | `lambda: self._refresh_exceptions(user_requested=True)` · [src/angerona/gui/adaptation_workbench.py:817](../../src/angerona/gui/adaptation_workbench.py#L817) |
| Remove selected exception | QPushButton | `AdaptationWorkbench._build_exceptions_tab` | `self._remove_exception` · [src/angerona/gui/adaptation_workbench.py:819](../../src/angerona/gui/adaptation_workbench.py#L819) |
| 1. Preview adaptation | QPushButton | `AdaptationWorkbench._build_profiles_tab` | `self._preview_profile` · [src/angerona/gui/adaptation_workbench.py:852](../../src/angerona/gui/adaptation_workbench.py#L852) |
| 2. Test in sandbox | QPushButton | `AdaptationWorkbench._build_profiles_tab` | `self._run_sandbox` · [src/angerona/gui/adaptation_workbench.py:854](../../src/angerona/gui/adaptation_workbench.py#L854) |
| Copy complete review | QPushButton | `AdaptationWorkbench._build_profiles_tab` | `lambda: QApplication.clipboard().setText(self.plan_text.toPlainText() + '\n\n' + json.dumps((self._latest_review or {}).get('simulation') or {}, indent=2, default=str))` · [src/angerona/gui/adaptation_workbench.py:909](../../src/angerona/gui/adaptation_workbench.py#L909) |
| 3. ADAPT HOST with this preview… | QPushButton | `AdaptationWorkbench._build_profiles_tab` | `self._apply_profile` · [src/angerona/gui/adaptation_workbench.py:916](../../src/angerona/gui/adaptation_workbench.py#L916) |
| Refresh | QPushButton | `AdaptationWorkbench._build_profiles_tab` | `lambda: self._refresh_snapshots(user_requested=True)` · [src/angerona/gui/adaptation_workbench.py:934](../../src/angerona/gui/adaptation_workbench.py#L934) |
| Roll back selected snapshot… | QPushButton | `AdaptationWorkbench._build_profiles_tab` | `self._rollback_selected` · [src/angerona/gui/adaptation_workbench.py:936](../../src/angerona/gui/adaptation_workbench.py#L936) |
| Capture immutable host baseline… | QPushButton | `AdaptationWorkbench._build_profiles_tab` | `self._capture_security_baseline` · [src/angerona/gui/adaptation_workbench.py:938](../../src/angerona/gui/adaptation_workbench.py#L938) |
| Restore host baseline… | QPushButton | `AdaptationWorkbench._build_profiles_tab` | `self._restore_security_baseline` · [src/angerona/gui/adaptation_workbench.py:940](../../src/angerona/gui/adaptation_workbench.py#L940) |
| Run no-write simulation | QPushButton | `AdaptationWorkbench._build_sandbox_tab` | `self._run_sandbox` · [src/angerona/gui/adaptation_workbench.py:961](../../src/angerona/gui/adaptation_workbench.py#L961) |
| Monitor configured contexts | QCheckBox | `AdaptationWorkbench._build_automation_tab` | `self._automation_changed` · [src/angerona/gui/adaptation_workbench.py:991](../../src/angerona/gui/adaptation_workbench.py#L991) |
| Unattended apply (unavailable) | QCheckBox | `AdaptationWorkbench._build_automation_tab` | `self._auto_apply_changed` · [src/angerona/gui/adaptation_workbench.py:992](../../src/angerona/gui/adaptation_workbench.py#L992) |
| Evaluate current context now | QPushButton | `AdaptationWorkbench._build_automation_tab` | `self._evaluate_context` · [src/angerona/gui/adaptation_workbench.py:1001](../../src/angerona/gui/adaptation_workbench.py#L1001) |
| Add trigger mapping | QPushButton | `AdaptationWorkbench._build_automation_tab` | `self._add_trigger` · [src/angerona/gui/adaptation_workbench.py:1021](../../src/angerona/gui/adaptation_workbench.py#L1021) |
| Remove selected rule | QPushButton | `AdaptationWorkbench._build_automation_tab` | `self._remove_trigger` · [src/angerona/gui/adaptation_workbench.py:1034](../../src/angerona/gui/adaptation_workbench.py#L1034) |
| Reset circuit breaker… | QPushButton | `AdaptationWorkbench._build_automation_tab` | `self._reset_breaker` · [src/angerona/gui/adaptation_workbench.py:1036](../../src/angerona/gui/adaptation_workbench.py#L1036) |
| Refresh activity | QPushButton | `AdaptationWorkbench._build_activity_tab` | `lambda: self._refresh_activity(user_requested=True)` · [src/angerona/gui/adaptation_workbench.py:1066](../../src/angerona/gui/adaptation_workbench.py#L1066) |
| Copy details | QPushButton | `AdaptationWorkbench._show_notice` | `lambda: QApplication.clipboard().setText(body.toPlainText())` · [src/angerona/gui/adaptation_workbench.py:1146](../../src/angerona/gui/adaptation_workbench.py#L1146) |
| Close | QPushButton | `AdaptationWorkbench._show_notice` | `dialog.close` · [src/angerona/gui/adaptation_workbench.py:1148](../../src/angerona/gui/adaptation_workbench.py#L1148) |
| Approve exact operation | QPushButton | `AdaptationWorkbench._confirm_operation` | [src/angerona/gui/adaptation_workbench.py:1178](../../src/angerona/gui/adaptation_workbench.py#L1178) |
| Cancel | QPushButton | `AdaptationWorkbench._confirm_operation` | [src/angerona/gui/adaptation_workbench.py:1178](../../src/angerona/gui/adaptation_workbench.py#L1178) |

## Aegis path

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Paths | Tab | `AegisPathWidget.__init__` | [src/angerona/gui/aegis_path.py:243](../../src/angerona/gui/aegis_path.py#L243) |
| Targets | Tab | `AegisPathWidget.__init__` | [src/angerona/gui/aegis_path.py:244](../../src/angerona/gui/aegis_path.py#L244) |
| Entry points | Tab | `AegisPathWidget.__init__` | [src/angerona/gui/aegis_path.py:245](../../src/angerona/gui/aegis_path.py#L245) |
| Breakpoints | Tab | `AegisPathWidget.__init__` | [src/angerona/gui/aegis_path.py:246](../../src/angerona/gui/aegis_path.py#L246) |
| What if this breakpoint were applied? | QPushButton | `AegisPathWidget.__init__` | `self._run_what_if` · [src/angerona/gui/aegis_path.py:266](../../src/angerona/gui/aegis_path.py#L266) |

## Ai consult dialog

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Review edits | QPushButton | `AIConsultDialog.__init__` | `self._review_edits` · [src/angerona/gui/ai_consult_dialog.py:116](../../src/angerona/gui/ai_consult_dialog.py#L116) |
| Send reviewed request | QPushButton | `AIConsultDialog.__init__` | `self._send_reviewed` · [src/angerona/gui/ai_consult_dialog.py:118](../../src/angerona/gui/ai_consult_dialog.py#L118) |
| Preview follow-up | QPushButton | `AIConsultDialog.__init__` | `self._send_followup` · [src/angerona/gui/ai_consult_dialog.py:134](../../src/angerona/gui/ai_consult_dialog.py#L134) |
| Review original request | QPushButton | `AIConsultDialog.__init__` | `self._start` · [src/angerona/gui/ai_consult_dialog.py:141](../../src/angerona/gui/ai_consult_dialog.py#L141) |
| Ask AI | QPushButton | `AIConsultDialog.__init__` | `self._reveal_prompt` · [src/angerona/gui/ai_consult_dialog.py:142](../../src/angerona/gui/ai_consult_dialog.py#L142) |
| Save to computer… | QPushButton | `AIConsultDialog.__init__` | `self._save` · [src/angerona/gui/ai_consult_dialog.py:143](../../src/angerona/gui/ai_consult_dialog.py#L143) |
| Discard | QPushButton | `AIConsultDialog.__init__` | `self.close` · [src/angerona/gui/ai_consult_dialog.py:144](../../src/angerona/gui/ai_consult_dialog.py#L144) |

## Alert preview

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Open | QPushButton | `AlertPreview.__init__` | `lambda _checked=False: self.open_requested.emit()` · [src/angerona/gui/alert_preview.py:34](../../src/angerona/gui/alert_preview.py#L34) |

## Analysis lab

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Set up Lab emulator… | QPushButton | `AnalysisLabPanel.__init__` | `self._setup` · [src/angerona/gui/analysis_lab.py:60](../../src/angerona/gui/analysis_lab.py#L60) |
| Prepare runtime | QPushButton | `AnalysisLabPanel.__init__` | `self._prepare` · [src/angerona/gui/analysis_lab.py:61](../../src/angerona/gui/analysis_lab.py#L61) |
| Check readiness | QPushButton | `AnalysisLabPanel.__init__` | `self._check` · [src/angerona/gui/analysis_lab.py:62](../../src/angerona/gui/analysis_lab.py#L62) |
| Clear interrupted jobs | QPushButton | `AnalysisLabPanel.__init__` | `self._cleanup` · [src/angerona/gui/analysis_lab.py:63](../../src/angerona/gui/analysis_lab.py#L63) |
| Browse… | QPushButton | `AnalysisLabPanel.__init__` | `self._browse` · [src/angerona/gui/analysis_lab.py:80](../../src/angerona/gui/analysis_lab.py#L80) |
| Run analysis | QPushButton | `AnalysisLabPanel.__init__` | `self._run` · [src/angerona/gui/analysis_lab.py:88](../../src/angerona/gui/analysis_lab.py#L88) |
| Cancel analysis | QPushButton | `AnalysisLabPanel.__init__` | `self.cancel_pending` · [src/angerona/gui/analysis_lab.py:89](../../src/angerona/gui/analysis_lab.py#L89) |
| Export report… | QPushButton | `AnalysisLabPanel.__init__` | `self._export` · [src/angerona/gui/analysis_lab.py:90](../../src/angerona/gui/analysis_lab.py#L90) |

## Analysis qemu setup

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Download and configure the optional Lab emulator | QPushButton | `QEMUSetupDialog.__init__` | `self._install` · [src/angerona/gui/analysis_qemu_setup.py:52](../../src/angerona/gui/analysis_qemu_setup.py#L52) |
| Separate VMware setup (not required for this Lab)… | QPushButton | `QEMUSetupDialog.__init__` | `self._vmware` · [src/angerona/gui/analysis_qemu_setup.py:57](../../src/angerona/gui/analysis_qemu_setup.py#L57) |
| Skip / close | QPushButton | `QEMUSetupDialog.__init__` | `self.reject` · [src/angerona/gui/analysis_qemu_setup.py:66](../../src/angerona/gui/analysis_qemu_setup.py#L66) |

## Analysis vmware setup

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Open official Broadcom download portal | QPushButton | `VMwareSetupDialog.__init__` | `lambda: QDesktopServices.openUrl(QUrl(setup.DOWNLOAD_URL))` · [src/angerona/gui/analysis_vmware_setup.py:45](../../src/angerona/gui/analysis_vmware_setup.py#L45) |
| Official download instructions | QPushButton | `VMwareSetupDialog.__init__` | `lambda: QDesktopServices.openUrl(QUrl(setup.DOWNLOAD_HELP_URL))` · [src/angerona/gui/analysis_vmware_setup.py:46](../../src/angerona/gui/analysis_vmware_setup.py#L46) |
| Choose and install downloaded VMware… | QPushButton | `VMwareSetupDialog.__init__` | `self._install` · [src/angerona/gui/analysis_vmware_setup.py:47](../../src/angerona/gui/analysis_vmware_setup.py#L47) |
| Configure installed VMware service… | QPushButton | `VMwareSetupDialog.__init__` | `self._configure` · [src/angerona/gui/analysis_vmware_setup.py:48](../../src/angerona/gui/analysis_vmware_setup.py#L48) |
| Open Analysis Lab to prepare / check… | QPushButton | `VMwareSetupDialog.__init__` | `self._open_lab` · [src/angerona/gui/analysis_vmware_setup.py:49](../../src/angerona/gui/analysis_vmware_setup.py#L49) |
| Skip / close | QPushButton | `VMwareSetupDialog.__init__` | `self.reject` · [src/angerona/gui/analysis_vmware_setup.py:66](../../src/angerona/gui/analysis_vmware_setup.py#L66) |

## Aria hud

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| 🎙  VOICE & MIC | QPushButton | `AriaHud.__init__` | `lambda _checked=False: self.microphone_requested.emit(self.mic_button)` · [src/angerona/gui/aria_hud.py:264](../../src/angerona/gui/aria_hud.py#L264) |

## Attack heatmap

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Active only | QCheckBox | `AttackHeatmapWindow.__init__` | [src/angerona/gui/attack_heatmap.py:327](../../src/angerona/gui/attack_heatmap.py#L327) |
| Explain posture | QPushButton | `AttackHeatmapWindow.__init__` | `self._explain_posture` · [src/angerona/gui/attack_heatmap.py:331](../../src/angerona/gui/attack_heatmap.py#L331) |
| Export to Navigator | QPushButton | `AttackHeatmapWindow.__init__` | `self._export_navigator` · [src/angerona/gui/attack_heatmap.py:337](../../src/angerona/gui/attack_heatmap.py#L337) |
| Reset counts | QPushButton | `AttackHeatmapWindow.__init__` | `self._reset` · [src/angerona/gui/attack_heatmap.py:346](../../src/angerona/gui/attack_heatmap.py#L346) |
| 🔥  Live Heat | Tab | `AttackHeatmapWindow.__init__` | [src/angerona/gui/attack_heatmap.py:391](../../src/angerona/gui/attack_heatmap.py#L391) |
| 🛡  Coverage | Tab | `AttackHeatmapWindow.__init__` | [src/angerona/gui/attack_heatmap.py:392](../../src/angerona/gui/attack_heatmap.py#L392) |
| 📊  Top Techniques | Tab | `AttackHeatmapWindow.__init__` | [src/angerona/gui/attack_heatmap.py:393](../../src/angerona/gui/attack_heatmap.py#L393) |
| Close | QPushButton | `AttackHeatmapWindow._show_posture` | `self._posture_dlg.close` · [src/angerona/gui/attack_heatmap.py:801](../../src/angerona/gui/attack_heatmap.py#L801) |

## Breach display

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Generated label or icon | QToolButton | `AfterActionReportDialog.__init__` | `self._show_technical_details` · [src/angerona/gui/breach_display.py:636](../../src/angerona/gui/breach_display.py#L636) |
| Generated label or icon | QPushButton | `AfterActionReportDialog.__init__` | `self.show_investigation`, `self.show_trace`, `lambda _checked=False, selected=action: self.action_requested.emit(selected)` · [src/angerona/gui/breach_display.py:665](../../src/angerona/gui/breach_display.py#L665) |
| Copy complete JSON | QPushButton | `AfterActionReportDialog.__init__` | `self.copy_complete_report` · [src/angerona/gui/breach_display.py:682](../../src/angerona/gui/breach_display.py#L682) |
| Export complete JSON… | QPushButton | `AfterActionReportDialog.__init__` | `self.export_complete_report` · [src/angerona/gui/breach_display.py:685](../../src/angerona/gui/breach_display.py#L685) |

## Community tools

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Install selected | QPushButton | `CommunityToolsPanel.__init__` | `self._install` · [src/angerona/gui/community_tools.py:108](../../src/angerona/gui/community_tools.py#L108) |
| Uninstall | QPushButton | `CommunityToolsPanel.__init__` | `lambda: self._action('uninstall')` · [src/angerona/gui/community_tools.py:109](../../src/angerona/gui/community_tools.py#L109) |
| Run self-check | QPushButton | `CommunityToolsPanel.__init__` | `lambda: self._action('self_check')` · [src/angerona/gui/community_tools.py:110](../../src/angerona/gui/community_tools.py#L110) |
| Refresh | QPushButton | `CommunityToolsPanel.__init__` | `self.refresh` · [src/angerona/gui/community_tools.py:111](../../src/angerona/gui/community_tools.py#L111) |
| Create editable copy | QPushButton | `CommunityToolsPanel.__init__` | `lambda: self._action('create_sandbox')` · [src/angerona/gui/community_tools.py:112](../../src/angerona/gui/community_tools.py#L112) |
| Open upstream | QPushButton | `CommunityToolsPanel.__init__` | `self._open_upstream` · [src/angerona/gui/community_tools.py:123](../../src/angerona/gui/community_tools.py#L123) |
| Credits / licenses | QPushButton | `CommunityToolsPanel.__init__` | `self._show_credits` · [src/angerona/gui/community_tools.py:124](../../src/angerona/gui/community_tools.py#L124) |
| Source Library | QPushButton | `CommunityToolsPanel.__init__` | `lambda: self._open_source_review() if callable(self._open_source_review) else None` · [src/angerona/gui/community_tools.py:125](../../src/angerona/gui/community_tools.py#L125) |
| Overview / actions | Tab | `CommunityToolsPanel.__init__` | [src/angerona/gui/community_tools.py:146](../../src/angerona/gui/community_tools.py#L146) |
| Save copy | QPushButton | `CommunityToolsPanel.__init__` | `self._save` · [src/angerona/gui/community_tools.py:166](../../src/angerona/gui/community_tools.py#L166) |
| Show diff | QPushButton | `CommunityToolsPanel.__init__` | `lambda: self._sandbox_action('sandbox_diff')` · [src/angerona/gui/community_tools.py:167](../../src/angerona/gui/community_tools.py#L167) |
| Revert selected copy | QPushButton | `CommunityToolsPanel.__init__` | `lambda: self._sandbox_action('sandbox_revert')` · [src/angerona/gui/community_tools.py:168](../../src/angerona/gui/community_tools.py#L168) |
| Validate / analyze data | QPushButton | `CommunityToolsPanel.__init__` | `lambda: self._sandbox_action('sandbox_analysis')` · [src/angerona/gui/community_tools.py:169](../../src/angerona/gui/community_tools.py#L169) |
| Editable sandbox | Tab | `CommunityToolsPanel.__init__` | [src/angerona/gui/community_tools.py:173](../../src/angerona/gui/community_tools.py#L173) |
| Credits / licenses | Tab | `CommunityToolsPanel.__init__` | [src/angerona/gui/community_tools.py:176](../../src/angerona/gui/community_tools.py#L176) |
| VM analysis | Tab | `CommunityToolsPanel.__init__` | [src/angerona/gui/community_tools.py:179](../../src/angerona/gui/community_tools.py#L179) |
| Cancel this tool's action | QPushButton | `CommunityToolsPanel.__init__` | `self.cancel_selected` · [src/angerona/gui/community_tools.py:187](../../src/angerona/gui/community_tools.py#L187) |

## Context info

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Check Syntax | QPushButton | `SourceSandboxDialog.__init__` | `self._check_syntax` · [src/angerona/gui/context_info.py:115](../../src/angerona/gui/context_info.py#L115) |
| Save Sandbox Copy | QPushButton | `SourceSandboxDialog.__init__` | `self._save` · [src/angerona/gui/context_info.py:116](../../src/angerona/gui/context_info.py#L116) |
| Reset Current Copy | QPushButton | `SourceSandboxDialog.__init__` | `self._reset_current` · [src/angerona/gui/context_info.py:117](../../src/angerona/gui/context_info.py#L117) |
| Reset All Sandbox Changes | QPushButton | `SourceSandboxDialog.__init__` | `self._reset_all` · [src/angerona/gui/context_info.py:118](../../src/angerona/gui/context_info.py#L118) |
| Close | QPushButton | `SourceSandboxDialog.__init__` | `self.close` · [src/angerona/gui/context_info.py:119](../../src/angerona/gui/context_info.py#L119) |
| Open Code Sandbox | QPushButton | `ContextInfoTab.__init__` | `self._open_sandbox` · [src/angerona/gui/context_info.py:326](../../src/angerona/gui/context_info.py#L326) |
| Reset Sandbox Changes | QPushButton | `ContextInfoTab.__init__` | `self._reset_sandbox` · [src/angerona/gui/context_info.py:327](../../src/angerona/gui/context_info.py#L327) |
| Copy Locations | QPushButton | `ContextInfoTab.__init__` | `self._copy_locations` · [src/angerona/gui/context_info.py:328](../../src/angerona/gui/context_info.py#L328) |
| Info | Tab | `TabbedInfoController.__init__` | [src/angerona/gui/context_info.py:530](../../src/angerona/gui/context_info.py#L530) |

## Curated tools

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Generated label or icon | QPushButton | `_ScanObservedText.__init__` | `self._copy_text` · [src/angerona/gui/curated_tools.py:187](../../src/angerona/gui/curated_tools.py#L187) |
| Review scanner storage… | QPushButton | `CuratedToolsController.show_after_action` | `self.show_storage_review` · [src/angerona/gui/curated_tools.py:1377](../../src/angerona/gui/curated_tools.py#L1377) |
| Previous page | QPushButton | `ScannerStorageDialog.__init__` | `lambda: self._review_page(self._page - 1)` · [src/angerona/gui/curated_tools.py:1649](../../src/angerona/gui/curated_tools.py#L1649) |
| Next page | QPushButton | `ScannerStorageDialog.__init__` | `lambda: self._review_page(self._page + 1)` · [src/angerona/gui/curated_tools.py:1650](../../src/angerona/gui/curated_tools.py#L1650) |
| Refresh storage review | QPushButton | `ScannerStorageDialog.__init__` | `lambda: self._review_page(self._page)` · [src/angerona/gui/curated_tools.py:1662](../../src/angerona/gui/curated_tools.py#L1662) |
| Export selected report… | QPushButton | `ScannerStorageDialog.__init__` | `self._export` · [src/angerona/gui/curated_tools.py:1663](../../src/angerona/gui/curated_tools.py#L1663) |
| Delete selected report… | QPushButton | `ScannerStorageDialog.__init__` | `self._confirm_delete` · [src/angerona/gui/curated_tools.py:1664](../../src/angerona/gui/curated_tools.py#L1664) |
| Allow one extra report next scan… | QPushButton | `ScannerStorageDialog.__init__` | `self._confirm_extra_report` · [src/angerona/gui/curated_tools.py:1665](../../src/angerona/gui/curated_tools.py#L1665) |
| Close · keep evidence | QPushButton | `ScannerStorageDialog.__init__` | `self.close` · [src/angerona/gui/curated_tools.py:1666](../../src/angerona/gui/curated_tools.py#L1666) |
| Generated label or icon | QCheckBox | `CuratedToolsSettings.__init__` | [src/angerona/gui/curated_tools.py:1844](../../src/angerona/gui/curated_tools.py#L1844) |
| Generated label or icon | QCheckBox | `CuratedToolsSettings.__init__` | [src/angerona/gui/curated_tools.py:1851](../../src/angerona/gui/curated_tools.py#L1851) |
| Save tool settings | QPushButton | `CuratedToolsSettings.__init__` | `self._save` · [src/angerona/gui/curated_tools.py:1884](../../src/angerona/gui/curated_tools.py#L1884) |
| Delete scanner reports… | QPushButton | `CuratedToolsSettings.__init__` | `self._clear_reports` · [src/angerona/gui/curated_tools.py:1891](../../src/angerona/gui/curated_tools.py#L1891) |
| Review / export retained reports… | QPushButton | `CuratedToolsSettings.__init__` | `controller.show_storage_review` · [src/angerona/gui/curated_tools.py:1895](../../src/angerona/gui/curated_tools.py#L1895) |
| Choose evidence folder… | QPushButton | `SpywareScanControls.__init__` | `self._choose_scope_folder` · [src/angerona/gui/curated_tools.py:2102](../../src/angerona/gui/curated_tools.py#L2102) |
| Native SpywareGuard | QCheckBox | `SpywareScanControls.__init__` | `self._update_setup_summary` · [src/angerona/gui/curated_tools.py:2113](../../src/angerona/gui/curated_tools.py#L2113) |
| Zero-Breach Toolkit | QCheckBox | `SpywareScanControls.__init__` | `self._update_setup_summary` · [src/angerona/gui/curated_tools.py:2115](../../src/angerona/gui/curated_tools.py#L2115) |
| Run once a day | QCheckBox | `SpywareScanControls.__init__` | [src/angerona/gui/curated_tools.py:2157](../../src/angerona/gui/curated_tools.py#L2157) |
| Save automatic scan settings | QPushButton | `SpywareScanControls.__init__` | `lambda: self.controller.save_options({'spyware_scan_auto_enabled': self.auto_scan_enabled.isChecked(), 'spyware_scan_auto_scope': self.auto_scan_scope.currentData()})` · [src/angerona/gui/curated_tools.py:2164](../../src/angerona/gui/curated_tools.py#L2164) |
| Stop scan | QPushButton | `SpywareScanControls.__init__` | `self.controller.cancel` · [src/angerona/gui/curated_tools.py:2193](../../src/angerona/gui/curated_tools.py#L2193) |
| Review scanner storage… | QPushButton | `SpywareScanControls.__init__` | `lambda: getattr(self.controller, 'show_storage_review', lambda: None)()` · [src/angerona/gui/curated_tools.py:2243](../../src/angerona/gui/curated_tools.py#L2243) |
| Install / repair | QPushButton | `CuratedScannerWidget.__init__` | `self.controller.prepare` · [src/angerona/gui/curated_tools.py:2863](../../src/angerona/gui/curated_tools.py#L2863) |
| Run scan | QPushButton | `CuratedScannerWidget.__init__` | `lambda: self._scan()` · [src/angerona/gui/curated_tools.py:2864](../../src/angerona/gui/curated_tools.py#L2864) |
| Spyware Scan | QPushButton | `CuratedScannerWidget.__init__` | `lambda: self._scan(priority=True)` · [src/angerona/gui/curated_tools.py:2865](../../src/angerona/gui/curated_tools.py#L2865) |
| Stop scan | QPushButton | `CuratedScannerWidget.__init__` | `self.controller.cancel` · [src/angerona/gui/curated_tools.py:2867](../../src/angerona/gui/curated_tools.py#L2867) |
| Credits | QPushButton | `CuratedScannerWidget.__init__` | `self._request_credits` · [src/angerona/gui/curated_tools.py:2868](../../src/angerona/gui/curated_tools.py#L2868) |
| Generated label or icon | QToolButton | `CuratedScannerWidget.__init__` | `self._toggle_options` · [src/angerona/gui/curated_tools.py:2891](../../src/angerona/gui/curated_tools.py#L2891) |
| Choose folder… | QPushButton | `CuratedScannerWidget.__init__` | `lambda: self._choose(True)` · [src/angerona/gui/curated_tools.py:2921](../../src/angerona/gui/curated_tools.py#L2921) |
| Choose file… | QPushButton | `CuratedScannerWidget.__init__` | `lambda: self._choose(False)` · [src/angerona/gui/curated_tools.py:2922](../../src/angerona/gui/curated_tools.py#L2922) |
| Indicator file… | QPushButton | `CuratedScannerWidget.__init__` | `self._choose_iocs` · [src/angerona/gui/curated_tools.py:2923](../../src/angerona/gui/curated_tools.py#L2923) |
| Quick scan (records skipped hashing) | QCheckBox | `CuratedScannerWidget.__init__` | [src/angerona/gui/curated_tools.py:2931](../../src/angerona/gui/curated_tools.py#L2931) |
| Preview scope without claiming a completed scan | QCheckBox | `CuratedScannerWidget.__init__` | [src/angerona/gui/curated_tools.py:2932](../../src/angerona/gui/curated_tools.py#L2932) |
| Include existing Windows event records | QCheckBox | `CuratedScannerWidget.__init__` | [src/angerona/gui/curated_tools.py:2933](../../src/angerona/gui/curated_tools.py#L2933) |
| Verify / self-test | QPushButton | `CuratedScannerWidget.__init__` | `self.controller.self_test` · [src/angerona/gui/curated_tools.py:2943](../../src/angerona/gui/curated_tools.py#L2943) |
| Settings | QPushButton | `CuratedScannerWidget.__init__` | `self._show_settings` · [src/angerona/gui/curated_tools.py:2944](../../src/angerona/gui/curated_tools.py#L2944) |
| Analysis / sandbox | QPushButton | `CuratedScannerWidget.__init__` | `self.analysis_requested.emit` · [src/angerona/gui/curated_tools.py:2945](../../src/angerona/gui/curated_tools.py#L2945) |
| Advanced toolkit options… | QPushButton | `CuratedScannerWidget.__init__` | `self._show_advanced` · [src/angerona/gui/curated_tools.py:2946](../../src/angerona/gui/curated_tools.py#L2946) |
| Revert | QPushButton | `CuratedScannerWidget.__init__` | `self._revert` · [src/angerona/gui/curated_tools.py:2947](../../src/angerona/gui/curated_tools.py#L2947) |
| Project ↗ | QPushButton | `CuratedScannerWidget.__init__` | `lambda: _open_link(_PROJECT)` · [src/angerona/gui/curated_tools.py:2948](../../src/angerona/gui/curated_tools.py#L2948) |
| Investigate | QPushButton | `CuratedScannerWidget.__init__` | `self._investigate` · [src/angerona/gui/curated_tools.py:2968](../../src/angerona/gui/curated_tools.py#L2968) |
| Trace evidence | QPushButton | `CuratedScannerWidget.__init__` | `lambda: self._investigate(trace=True)` · [src/angerona/gui/curated_tools.py:2970](../../src/angerona/gui/curated_tools.py#L2970) |
| Official pinned release / downloads ↗ | QPushButton | `CuratedScannerWidget._show_advanced` | `lambda: _open_link(_RELEASE)` · [src/angerona/gui/curated_tools.py:3147](../../src/angerona/gui/curated_tools.py#L3147) |
| Check advanced adapter status | QPushButton | `CuratedScannerWidget._show_advanced` | `self.controller.open_tool` · [src/angerona/gui/curated_tools.py:3149](../../src/angerona/gui/curated_tools.py#L3149) |
| Open selected link ↗ | QPushButton | `CuratedScannerWidget._show_credits` | `lambda: _open_link(choices.currentData())` · [src/angerona/gui/curated_tools.py:3194](../../src/angerona/gui/curated_tools.py#L3194) |
| Curated scanners | Tab | `GitHubToolsDialog.__init__` | [src/angerona/gui/curated_tools.py:3234](../../src/angerona/gui/curated_tools.py#L3234) |
| Source library & analysis | Tab | `GitHubToolsDialog.__init__` | [src/angerona/gui/curated_tools.py:3244](../../src/angerona/gui/curated_tools.py#L3244) |
| Suggested tools | Tab | `GitHubToolsDialog.__init__` | [src/angerona/gui/curated_tools.py:3258](../../src/angerona/gui/curated_tools.py#L3258) |
| Rules & Playbooks | Tab | `GitHubToolsDialog.__init__` | [src/angerona/gui/curated_tools.py:3262](../../src/angerona/gui/curated_tools.py#L3262) |
| Settings | Tab | `GitHubToolsDialog.__init__` | [src/angerona/gui/curated_tools.py:3267](../../src/angerona/gui/curated_tools.py#L3267) |

## Cve analysis window

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| ↺  Refresh CVEs | QPushButton | `CveAnalysisWindow.__init__` | `self._load_cves` · [src/angerona/gui/cve_analysis_window.py:372](../../src/angerona/gui/cve_analysis_window.py#L372) |
| ⚡  Generate AI Analysis | QPushButton | `CveAnalysisWindow.__init__` | `self._run_ai_analysis` · [src/angerona/gui/cve_analysis_window.py:433](../../src/angerona/gui/cve_analysis_window.py#L433) |
| 🌐  Consult AI | QPushButton | `CveAnalysisWindow.__init__` | `lambda: self._open_online_ai(local_ok=True)` · [src/angerona/gui/cve_analysis_window.py:442](../../src/angerona/gui/cve_analysis_window.py#L442) |
| 💡  AI Proposed Solution | QPushButton | `CveAnalysisWindow.__init__` | `lambda: self._open_online_ai(local_ok=False)` · [src/angerona/gui/cve_analysis_window.py:452](../../src/angerona/gui/cve_analysis_window.py#L452) |

## Dashboard details

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Close | QPushButton | `FuturisticDetailDialog.__init__` | `self.close` · [src/angerona/gui/dashboard_details.py:239](../../src/angerona/gui/dashboard_details.py#L239) |
| Run in dashboard console | QPushButton | `ConsoleDetailDialog.__init__` | `self._run` · [src/angerona/gui/dashboard_details.py:412](../../src/angerona/gui/dashboard_details.py#L412) |
| Ask ARIA | QPushButton | `AriaDetailDialog.__init__` | `self._ask` · [src/angerona/gui/dashboard_details.py:499](../../src/angerona/gui/dashboard_details.py#L499) |
| Voice & microphone settings | QPushButton | `AriaDetailDialog.__init__` | `lambda: self._open_from(voice, owner._open_voice_settings)` · [src/angerona/gui/dashboard_details.py:502](../../src/angerona/gui/dashboard_details.py#L502) |

## Detection forge

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Import verified package… | QPushButton | `DetectionForgeWidget.__init__` | `self._import_package` · [src/angerona/gui/detection_forge.py:591](../../src/angerona/gui/detection_forge.py#L591) |
| Refresh exact gates | QPushButton | `DetectionForgeWidget.__init__` | `self.refresh` · [src/angerona/gui/detection_forge.py:593](../../src/angerona/gui/detection_forge.py#L593) |
| Preview sanitized export | QPushButton | `DetectionForgeWidget.__init__` | `self._show_export` · [src/angerona/gui/detection_forge.py:595](../../src/angerona/gui/detection_forge.py#L595) |
| Generated label | Tab | `DetectionForgeWidget.__init__` | [src/angerona/gui/detection_forge.py:609](../../src/angerona/gui/detection_forge.py#L609) |

## Display recovery

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Retry display | QPushButton | `DisplayRecoveryNotice.__init__` | `lambda: (self.hide(), retry())` · [src/angerona/gui/display_recovery.py:197](../../src/angerona/gui/display_recovery.py#L197) |
| Safe STOP | QPushButton | `DisplayRecoveryNotice.__init__` | `stop` · [src/angerona/gui/display_recovery.py:199](../../src/angerona/gui/display_recovery.py#L199) |
| Close notice | QPushButton | `DisplayRecoveryNotice.__init__` | `self.close` · [src/angerona/gui/display_recovery.py:201](../../src/angerona/gui/display_recovery.py#L201) |

## Engine console

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Start / reconnect | QPushButton | `EngineConsole.__init__` | `lambda: self._submit('connect')` · [src/angerona/gui/engine_console.py:218](../../src/angerona/gui/engine_console.py#L218) |
| Chill mode | QCheckBox | `EngineConsole.__init__` | `lambda checked: self._submit('chill', checked)` · [src/angerona/gui/engine_console.py:221](../../src/angerona/gui/engine_console.py#L221) |
| Stop protection… | QPushButton | `EngineConsole.__init__` | `self._stop_protection` · [src/angerona/gui/engine_console.py:225](../../src/angerona/gui/engine_console.py#L225) |
| Clean old alert files | QCheckBox | `EngineConsole.__init__` | [src/angerona/gui/engine_console.py:230](../../src/angerona/gui/engine_console.py#L230) |
| Save alert limits | QPushButton | `EngineConsole.__init__` | `lambda: self._submit('retention', {'alert_retention_enabled': self.retention_enabled.isChecked(), 'alert_retention_days': self.retention_days.value(), 'alert_retention_max_mib': self.retention_limit.value()})` · [src/angerona/gui/engine_console.py:243](../../src/angerona/gui/engine_console.py#L243) |
| Generated label or icon | QPushButton | `EngineConsole.__init__` | `lambda _checked=False, op=operation: self._module_command(op)` · [src/angerona/gui/engine_console.py:265](../../src/angerona/gui/engine_console.py#L265) |

## Fleet center

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Refresh local evidence | QPushButton | `FleetCenterWidget.__init__` | `self.refresh` · [src/angerona/gui/fleet_center.py:75](../../src/angerona/gui/fleet_center.py#L75) |
| Preview rollback plan | QPushButton | `FleetCenterWidget.__init__` | `self._preview_rollback` · [src/angerona/gui/fleet_center.py:78](../../src/angerona/gui/fleet_center.py#L78) |
| Device health | Tab | `FleetCenterWidget.__init__` | [src/angerona/gui/fleet_center.py:97](../../src/angerona/gui/fleet_center.py#L97) |
| Policy rollouts | Tab | `FleetCenterWidget.__init__` | [src/angerona/gui/fleet_center.py:106](../../src/angerona/gui/fleet_center.py#L106) |
| Enrollment grants | Tab | `FleetCenterWidget.__init__` | [src/angerona/gui/fleet_center.py:115](../../src/angerona/gui/fleet_center.py#L115) |
| Close | QPushButton | `FleetCenterDialog.__init__` | `self.close` · [src/angerona/gui/fleet_center.py:376](../../src/angerona/gui/fleet_center.py#L376) |

## Flow window

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Host telemetry ▲ | QPushButton | `FlowWindow.__init__` | `self._toggle_tele_panel`, `lambda on: tele_toggle.setText('Host telemetry ▲' if on else 'Host telemetry ▼')` · [src/angerona/gui/flow_window.py:231](../../src/angerona/gui/flow_window.py#L231) |
| SentinelLens | QPushButton | `FlowWindow.__init__` | `self._open_sentinel_lens` · [src/angerona/gui/flow_window.py:237](../../src/angerona/gui/flow_window.py#L237) |
| Fit | QPushButton | `FlowWindow.__init__` | `self._fit_scene` · [src/angerona/gui/flow_window.py:244](../../src/angerona/gui/flow_window.py#L244) |
| Close | QPushButton | `FlowWindow.__init__` | `self.close` · [src/angerona/gui/flow_window.py:246](../../src/angerona/gui/flow_window.py#L246) |

## Github tools

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Source | Tab | `GitHubToolsPanel.__init__` | [src/angerona/gui/github_tools.py:97](../../src/angerona/gui/github_tools.py#L97) |
| Verification | Tab | `GitHubToolsPanel.__init__` | [src/angerona/gui/github_tools.py:100](../../src/angerona/gui/github_tools.py#L100) |
| Analysis Lab | Tab | `GitHubToolsPanel.__init__` | [src/angerona/gui/github_tools.py:103](../../src/angerona/gui/github_tools.py#L103) |
| Resolve revision | QPushButton | `GitHubToolsPanel.__init__` | `self._resolve` · [src/angerona/gui/github_tools.py:111](../../src/angerona/gui/github_tools.py#L111) |
| Import pinned source | QPushButton | `GitHubToolsPanel.__init__` | `self._import` · [src/angerona/gui/github_tools.py:112](../../src/angerona/gui/github_tools.py#L112) |
| Mark reviewed | QPushButton | `GitHubToolsPanel.__init__` | `lambda: self._review('reviewed')` · [src/angerona/gui/github_tools.py:113](../../src/angerona/gui/github_tools.py#L113) |
| Revoke | QPushButton | `GitHubToolsPanel.__init__` | `lambda: self._review('revoked')` · [src/angerona/gui/github_tools.py:114](../../src/angerona/gui/github_tools.py#L114) |
| Cancel | QPushButton | `GitHubToolsPanel.__init__` | `self.cancel_pending` · [src/angerona/gui/github_tools.py:115](../../src/angerona/gui/github_tools.py#L115) |

## Incident timeline page

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| ↻ Refresh | QPushButton | `IncidentTimelineDialog.__init__` | `self._refresh` · [src/angerona/gui/incident_timeline_page.py:51](../../src/angerona/gui/incident_timeline_page.py#L51) |
| ⬇ Export JSON | QPushButton | `IncidentTimelineDialog.__init__` | `self._export` · [src/angerona/gui/incident_timeline_page.py:52](../../src/angerona/gui/incident_timeline_page.py#L52) |
| Close | QPushButton | `IncidentTimelineDialog.__init__` | `self.close` · [src/angerona/gui/incident_timeline_page.py:66](../../src/angerona/gui/incident_timeline_page.py#L66) |

## Installed startup controls

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Check | QPushButton | `InstalledStartupControls.__init__` | `self.request_status` · [src/angerona/gui/installed_startup_controls.py:176](../../src/angerona/gui/installed_startup_controls.py#L176) |
| Info | QPushButton | `InstalledStartupControls.__init__` | `lambda: self._enrollment_info.setVisible(self.enrollment_info_button.isChecked())` · [src/angerona/gui/installed_startup_controls.py:177](../../src/angerona/gui/installed_startup_controls.py#L177) |
| Remove… | QPushButton | `InstalledStartupControls.__init__` | `partial(self._confirm, 'revoke')` · [src/angerona/gui/installed_startup_controls.py:179](../../src/angerona/gui/installed_startup_controls.py#L179) |

## Live debug panel

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Connect | QPushButton | `LiveDebugPanel.__init__` | `self.connect_to_pid` · [src/angerona/gui/live_debug_panel.py:377](../../src/angerona/gui/live_debug_panel.py#L377) |
| Disconnect | QPushButton | `LiveDebugPanel.__init__` | `self.disconnect_stream` · [src/angerona/gui/live_debug_panel.py:380](../../src/angerona/gui/live_debug_panel.py#L380) |
| Add local review | QPushButton | `LiveDebugPanel.__init__` | `lambda: self.annotate_selected()` · [src/angerona/gui/live_debug_panel.py:421](../../src/angerona/gui/live_debug_panel.py#L421) |
| Export selected… | QPushButton | `LiveDebugPanel.__init__` | `lambda: self.export_selected()` · [src/angerona/gui/live_debug_panel.py:424](../../src/angerona/gui/live_debug_panel.py#L424) |

## Main window

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| ADAPTATION | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_header_action(adaptation_btn, self._open_adaptation, '#67e8f9')` · [src/angerona/gui/main_window.py:423](../../src/angerona/gui/main_window.py#L423) |
| SELF-TEST | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_self_test()` · [src/angerona/gui/main_window.py:434](../../src/angerona/gui/main_window.py#L434) |
| RED TEAM SIMULATION | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_header_action(sim_btn, self._open_simulation, '#fb7185')` · [src/angerona/gui/main_window.py:448](../../src/angerona/gui/main_window.py#L448) |
| CHILL MODE | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._toggle_eco_mode()` · [src/angerona/gui/main_window.py:473](../../src/angerona/gui/main_window.py#L473) |
| WORLD VIEW | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_header_action(worldview_btn, self._open_worldview, '#38bdf8')` · [src/angerona/gui/main_window.py:533](../../src/angerona/gui/main_window.py#L533) |
| SUITE MAP · 3D | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_header_action(self._suite_map_btn, self._open_suite_map, '#22d3ee')` · [src/angerona/gui/main_window.py:543](../../src/angerona/gui/main_window.py#L543) |
| ATT&CK MAP | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_header_action(attack_heatmap_btn, self._open_attack_heatmap, '#fb923c')` · [src/angerona/gui/main_window.py:551](../../src/angerona/gui/main_window.py#L551) |
| THREAT INTEL | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_header_action(self.threat_intel_btn, self._open_threat_intel, '#60a5fa')` · [src/angerona/gui/main_window.py:563](../../src/angerona/gui/main_window.py#L563) |
| SPYWAREGUARD | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_header_action(self._spyware_guard_btn, self._open_spyware_guard, '#94a3b8')` · [src/angerona/gui/main_window.py:573](../../src/angerona/gui/main_window.py#L573) |
| GITHUB TOOLS | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_header_action(self._github_tools_btn, self._open_github_tools, '#e2e8f0')` · [src/angerona/gui/main_window.py:591](../../src/angerona/gui/main_window.py#L591) |
| RULES & PLAYBOOKS | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_header_action(self._rules_playbooks_btn, self._open_rules_playbooks, '#a78bfa')` · [src/angerona/gui/main_window.py:600](../../src/angerona/gui/main_window.py#L600) |
| FORENSICS | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_header_action(forensics_btn, self._open_forensics_hub, '#c084fc')` · [src/angerona/gui/main_window.py:611](../../src/angerona/gui/main_window.py#L611) |
| LOCAL SOC | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_header_action(operations_btn, self._open_operations_center, '#22d3ee')` · [src/angerona/gui/main_window.py:621](../../src/angerona/gui/main_window.py#L621) |
| CONSOLE | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_header_action(console_btn, self._open_upgrade_console, '#2dd4bf')` · [src/angerona/gui/main_window.py:632](../../src/angerona/gui/main_window.py#L632) |
| SETUP | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_header_action(setup_btn, self._open_setup, '#f472b6')` · [src/angerona/gui/main_window.py:642](../../src/angerona/gui/main_window.py#L642) |
| HELP | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_header_action(self._help_btn, self._open_help, '#facc15')` · [src/angerona/gui/main_window.py:652](../../src/angerona/gui/main_window.py#L652) |
| SETTINGS | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_header_action(settings_btn, self._open_settings, '#cbd5e1')` · [src/angerona/gui/main_window.py:662](../../src/angerona/gui/main_window.py#L662) |
| STOP | HeaderActionButton | `MainWindow.__init__` | `lambda _checked=False: self._run_header_action(stop_btn, self._full_shutdown, '#ef4444')` · [src/angerona/gui/main_window.py:676](../../src/angerona/gui/main_window.py#L676) |
| Live Alerts | Tab | `MainWindow.__init__` | [src/angerona/gui/main_window.py:754](../../src/angerona/gui/main_window.py#L754) |
| SOAR Queue | Tab | `MainWindow.__init__` | [src/angerona/gui/main_window.py:755](../../src/angerona/gui/main_window.py#L755) |
| 🛡 Scan Center | Tab | `MainWindow.__init__` | [src/angerona/gui/main_window.py:756](../../src/angerona/gui/main_window.py#L756) |
| UGCAP | Tab | `MainWindow.__init__` | [src/angerona/gui/main_window.py:757](../../src/angerona/gui/main_window.py#L757) |
| Workspace | Tab | `MainWindow.__init__` | [src/angerona/gui/main_window.py:853](../../src/angerona/gui/main_window.py#L853) |
| Updates | Menu | `MainWindow.__init__` | [src/angerona/gui/main_window.py:1060](../../src/angerona/gui/main_window.py#L1060) |
| Orbital overview | Tab | `MainWindow._apply_dashboard_display` | [src/angerona/gui/main_window.py:1377](../../src/angerona/gui/main_window.py#L1377) |
| Close | QPushButton | `MainWindow._open_usb_scan_review.create` | `dialog.close` · [src/angerona/gui/main_window.py:1951](../../src/angerona/gui/main_window.py#L1951) |
| Generated label | Tab | `MainWindow._open_help` | [src/angerona/gui/main_window.py:6028](../../src/angerona/gui/main_window.py#L6028) |
| ▶  Take the interactive tour | QPushButton | `MainWindow._open_help` | `lambda: (dlg.accept(), self._start_tour())` · [src/angerona/gui/main_window.py:6038](../../src/angerona/gui/main_window.py#L6038) |
| Close | QPushButton | `MainWindow._open_help` | `dlg.close` · [src/angerona/gui/main_window.py:6040](../../src/angerona/gui/main_window.py#L6040) |
| Open | QPushButton | `MainWindow._open_forensics_hub` | `_make(cb)` · [src/angerona/gui/main_window.py:6217](../../src/angerona/gui/main_window.py#L6217) |
| Close | QPushButton | `MainWindow._open_forensics_hub` | `dlg.close` · [src/angerona/gui/main_window.py:6225](../../src/angerona/gui/main_window.py#L6225) |
| Open Angerona | QAction | `MainWindow._build_tray` | `self._restore_from_background` · [src/angerona/gui/main_window.py:7134](../../src/angerona/gui/main_window.py#L7134) |
| Quit | QAction | `MainWindow._build_tray` | `self._quit` · [src/angerona/gui/main_window.py:7136](../../src/angerona/gui/main_window.py#L7136) |

## Normal log controls

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Block normal Python / Qt crash-log writes | QCheckBox | `NormalLogControls.__init__` | [src/angerona/gui/normal_log_controls.py:111](../../src/angerona/gui/normal_log_controls.py#L111) |
| Block for this run | QPushButton | `NormalLogControls.__init__` | `self._block` · [src/angerona/gui/normal_log_controls.py:129](../../src/angerona/gui/normal_log_controls.py#L129) |
| Allow within limits | QPushButton | `NormalLogControls.__init__` | `self._allow` · [src/angerona/gui/normal_log_controls.py:130](../../src/angerona/gui/normal_log_controls.py#L130) |
| Apply now / retry | QPushButton | `NormalLogControls.__init__` | `self._apply` · [src/angerona/gui/normal_log_controls.py:131](../../src/angerona/gui/normal_log_controls.py#L131) |

## Notification inbox

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Review | QPushButton | `_InboxDialog.__init__` | `self._review_selected` · [src/angerona/gui/notification_inbox.py:51](../../src/angerona/gui/notification_inbox.py#L51) |
| Dismiss | QPushButton | `_InboxDialog.__init__` | `self._dismiss_selected` · [src/angerona/gui/notification_inbox.py:52](../../src/angerona/gui/notification_inbox.py#L52) |
| Close | QPushButton | `_InboxDialog.__init__` | `self.close` · [src/angerona/gui/notification_inbox.py:53](../../src/angerona/gui/notification_inbox.py#L53) |

## Ollama status

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Start / check Ollama | QPushButton | `OllamaStatusPanel.__init__` | `self.start_service` · [src/angerona/gui/ollama_status.py:28](../../src/angerona/gui/ollama_status.py#L28) |

## Operations center

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| ↻ Refresh | QPushButton | `OperationsCenterDialog.__init__` | `lambda: self.refresh_all(user_requested=True)` · [src/angerona/gui/operations_center.py:317](../../src/angerona/gui/operations_center.py#L317) |
| Overview | Tab | `OperationsCenterDialog.__init__` | [src/angerona/gui/operations_center.py:327](../../src/angerona/gui/operations_center.py#L327) |
| Cases | Tab | `OperationsCenterDialog.__init__` | [src/angerona/gui/operations_center.py:328](../../src/angerona/gui/operations_center.py#L328) |
| Hunt | Tab | `OperationsCenterDialog.__init__` | [src/angerona/gui/operations_center.py:329](../../src/angerona/gui/operations_center.py#L329) |
| Assets | Tab | `OperationsCenterDialog.__init__` | [src/angerona/gui/operations_center.py:330](../../src/angerona/gui/operations_center.py#L330) |
| Detection Content | Tab | `OperationsCenterDialog.__init__` | [src/angerona/gui/operations_center.py:331](../../src/angerona/gui/operations_center.py#L331) |
| Fleet Center | Tab | `OperationsCenterDialog.__init__` | [src/angerona/gui/operations_center.py:339](../../src/angerona/gui/operations_center.py#L339) |
| DetectionForge | Tab | `OperationsCenterDialog.__init__` | [src/angerona/gui/operations_center.py:356](../../src/angerona/gui/operations_center.py#L356) |
| AegisPath | Tab | `OperationsCenterDialog.__init__` | [src/angerona/gui/operations_center.py:362](../../src/angerona/gui/operations_center.py#L362) |
| Parity & Interop | Tab | `OperationsCenterDialog.__init__` | [src/angerona/gui/operations_center.py:363](../../src/angerona/gui/operations_center.py#L363) |
| Audit | Tab | `OperationsCenterDialog.__init__` | [src/angerona/gui/operations_center.py:364](../../src/angerona/gui/operations_center.py#L364) |
| Generated label or icon | QPushButton | `OperationsCenterDialog.__init__` | `lambda _checked=False, name=key: self._callback(name)` · [src/angerona/gui/operations_center.py:377](../../src/angerona/gui/operations_center.py#L377) |
| Close | QPushButton | `OperationsCenterDialog.__init__` | `self.close` · [src/angerona/gui/operations_center.py:381](../../src/angerona/gui/operations_center.py#L381) |
| + Create | QPushButton | `OperationsCenterDialog._build_cases` | `self._create_case` · [src/angerona/gui/operations_center.py:499](../../src/angerona/gui/operations_center.py#L499) |
| Legal hold | QCheckBox | `OperationsCenterDialog._build_cases` | [src/angerona/gui/operations_center.py:536](../../src/angerona/gui/operations_center.py#L536) |
| Update | QPushButton | `OperationsCenterDialog._build_cases` | [src/angerona/gui/operations_center.py:537](../../src/angerona/gui/operations_center.py#L537) |
| Add note | QPushButton | `OperationsCenterDialog._build_cases` | `self._add_case_note` · [src/angerona/gui/operations_center.py:548](../../src/angerona/gui/operations_center.py#L548) |
| Export sanitized | QPushButton | `OperationsCenterDialog._build_cases` | `self._export_case` · [src/angerona/gui/operations_center.py:550](../../src/angerona/gui/operations_center.py#L550) |
| Run hunt | QPushButton | `OperationsCenterDialog._build_hunt` | `self._run_hunt` · [src/angerona/gui/operations_center.py:587](../../src/angerona/gui/operations_center.py#L587) |
| Attach evidence metadata | QPushButton | `OperationsCenterDialog._build_hunt` | `self._attach_hunt_evidence` · [src/angerona/gui/operations_center.py:603](../../src/angerona/gui/operations_center.py#L603) |
| Collect inventory | QPushButton | `OperationsCenterDialog._build_assets` | `self._collect_inventory` · [src/angerona/gui/operations_center.py:623](../../src/angerona/gui/operations_center.py#L623) |
| Stage package… | QPushButton | `OperationsCenterDialog._build_detections` | `self._stage_detection` · [src/angerona/gui/operations_center.py:642](../../src/angerona/gui/operations_center.py#L642) |
| Activate selected | QPushButton | `OperationsCenterDialog._build_detections` | `self._activate_detection` · [src/angerona/gui/operations_center.py:644](../../src/angerona/gui/operations_center.py#L644) |
| Rollback selected package | QPushButton | `OperationsCenterDialog._build_detections` | `self._rollback_detection` · [src/angerona/gui/operations_center.py:648](../../src/angerona/gui/operations_center.py#L648) |
| Export append-only audit… | QPushButton | `OperationsCenterDialog._build_audit` | `self._export_audit` · [src/angerona/gui/operations_center.py:677](../../src/angerona/gui/operations_center.py#L677) |
| Import local evidence… | QPushButton | `OperationsCenterDialog._build_interoperability` | `self._import_security_evidence` · [src/angerona/gui/operations_center.py:720](../../src/angerona/gui/operations_center.py#L720) |
| Run guarded snapshot | QPushButton | `OperationsCenterDialog._build_interoperability` | `self._run_osquery_snapshot` · [src/angerona/gui/operations_center.py:745](../../src/angerona/gui/operations_center.py#L745) |

## Pages

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Refresh | QPushButton | `EventsWindow.__init__` | `self._refresh` · [src/angerona/gui/pages.py:2001](../../src/angerona/gui/pages.py#L2001) |
| Close | QPushButton | `EventsWindow.__init__` | `self.close` · [src/angerona/gui/pages.py:2003](../../src/angerona/gui/pages.py#L2003) |
| Turn all on | QPushButton | `ModulesStatusWindow.__init__` | `self._turn_all_on` · [src/angerona/gui/pages.py:2379](../../src/angerona/gui/pages.py#L2379) |
| Refresh | QPushButton | `ModulesStatusWindow.__init__` | `self._refresh` · [src/angerona/gui/pages.py:2392](../../src/angerona/gui/pages.py#L2392) |
| Close | QPushButton | `ModulesStatusWindow.__init__` | `self.close` · [src/angerona/gui/pages.py:2394](../../src/angerona/gui/pages.py#L2394) |
| Generate advisory + vetted plan | QPushButton | `ThreatWindow.__init__` | `self._attempt_fix` · [src/angerona/gui/pages.py:2768](../../src/angerona/gui/pages.py#L2768) |
| Apply vetted typed fixes… | QPushButton | `ThreatWindow.__init__` | `self._apply_fix` · [src/angerona/gui/pages.py:2770](../../src/angerona/gui/pages.py#L2770) |
| Harden system | QPushButton | `ThreatWindow.__init__` | `self._harden` · [src/angerona/gui/pages.py:2773](../../src/angerona/gui/pages.py#L2773) |
| Blast radius | QPushButton | `ThreatWindow.__init__` | `self._open_blast` · [src/angerona/gui/pages.py:2775](../../src/angerona/gui/pages.py#L2775) |
| Shark vs Shield | QPushButton | `ThreatWindow.__init__` | `self._open_collision` · [src/angerona/gui/pages.py:2777](../../src/angerona/gui/pages.py#L2777) |
| Refresh | QPushButton | `ThreatWindow.__init__` | `self._refresh` · [src/angerona/gui/pages.py:2779](../../src/angerona/gui/pages.py#L2779) |
| Refresh | QPushButton | `BlastRadiusDialog.__init__` | `self._refresh` · [src/angerona/gui/pages.py:3126](../../src/angerona/gui/pages.py#L3126) |
| Close | QPushButton | `BlastRadiusDialog.__init__` | `self.close` · [src/angerona/gui/pages.py:3128](../../src/angerona/gui/pages.py#L3128) |
| Refresh | QPushButton | `CollisionView.__init__` | `self._refresh` · [src/angerona/gui/pages.py:3251](../../src/angerona/gui/pages.py#L3251) |
| Close | QPushButton | `CollisionView.__init__` | `self.close` · [src/angerona/gui/pages.py:3253](../../src/angerona/gui/pages.py#L3253) |
| Generated label or icon | QPushButton | `CollisionView._verdict_detail` | `lambda: webbrowser.open(url)` · [src/angerona/gui/pages.py:3351](../../src/angerona/gui/pages.py#L3351) |
| Copy details | QPushButton | `CollisionView._verdict_detail` | `lambda: QApplication.clipboard().setText(det.toPlainText())` · [src/angerona/gui/pages.py:3354](../../src/angerona/gui/pages.py#L3354) |
| Close | QPushButton | `CollisionView._verdict_detail` | `dlg.close` · [src/angerona/gui/pages.py:3357](../../src/angerona/gui/pages.py#L3357) |
| Shark — lure drops, discovery, BYOVD driver-drop, exfil markers | QCheckBox | `RedTeamSimulationDialog.__init__` | [src/angerona/gui/pages.py:3438](../../src/angerona/gui/pages.py#L3438) |
| APT Red-Team — credential-access, WMI persistence, defense-evasion markers | QCheckBox | `RedTeamSimulationDialog.__init__` | [src/angerona/gui/pages.py:3440](../../src/angerona/gui/pages.py#L3440) |
| New | QPushButton | `RedTeamSimulationDialog.__init__` | `self._new_custom` · [src/angerona/gui/pages.py:3480](../../src/angerona/gui/pages.py#L3480) |
| Save / Update | QPushButton | `RedTeamSimulationDialog.__init__` | `self._save_custom` · [src/angerona/gui/pages.py:3482](../../src/angerona/gui/pages.py#L3482) |
| Delete | QPushButton | `RedTeamSimulationDialog.__init__` | `self._delete_custom` · [src/angerona/gui/pages.py:3484](../../src/angerona/gui/pages.py#L3484) |
| Cancel | QPushButton | `RedTeamSimulationDialog.__init__` | `self.reject` · [src/angerona/gui/pages.py:3511](../../src/angerona/gui/pages.py#L3511) |
| ▶  Run simulation | QPushButton | `RedTeamSimulationDialog.__init__` | `self._on_run` · [src/angerona/gui/pages.py:3513](../../src/angerona/gui/pages.py#L3513) |
| Columns | QPushButton | `ModulesPanel.__init__` | `self._toggle_contract_columns` · [src/angerona/gui/pages.py:3743](../../src/angerona/gui/pages.py#L3743) |
| Filters | QPushButton | `ModulesPanel.__init__` | `self._filters_row.setVisible` · [src/angerona/gui/pages.py:3782](../../src/angerona/gui/pages.py#L3782) |
| Close | QPushButton | `ModuleHealthEvidenceDialog.__init__` | `self.close` · [src/angerona/gui/pages.py:4306](../../src/angerona/gui/pages.py#L4306) |
| Close | QPushButton | `ModuleAssuranceDialog.__init__` | `self.close` · [src/angerona/gui/pages.py:4440](../../src/angerona/gui/pages.py#L4440) |
| Overview | Tab | `ModuleInspector.__init__` | [src/angerona/gui/pages.py:4511](../../src/angerona/gui/pages.py#L4511) |
| Assurance | Tab | `ModuleInspector.__init__` | [src/angerona/gui/pages.py:4512](../../src/angerona/gui/pages.py#L4512) |
| Contract v12 | Tab | `ModuleInspector.__init__` | [src/angerona/gui/pages.py:4513](../../src/angerona/gui/pages.py#L4513) |
| ⚡ Performance | Tab | `ModuleInspector.__init__` | [src/angerona/gui/pages.py:4514](../../src/angerona/gui/pages.py#L4514) |
| 📋 History | Tab | `ModuleInspector.__init__` | [src/angerona/gui/pages.py:4515](../../src/angerona/gui/pages.py#L4515) |
| 🔗 Dependencies | Tab | `ModuleInspector.__init__` | [src/angerona/gui/pages.py:4516](../../src/angerona/gui/pages.py#L4516) |
| API Keys | Tab | `ModuleInspector.__init__` | [src/angerona/gui/pages.py:4518](../../src/angerona/gui/pages.py#L4518) |
| Help | Tab | `ModuleInspector.__init__` | [src/angerona/gui/pages.py:4519](../../src/angerona/gui/pages.py#L4519) |
| Generated label or icon | QPushButton | `ModuleInspector._overview_tab` | `self._open_health_evidence` · [src/angerona/gui/pages.py:4554](../../src/angerona/gui/pages.py#L4554) |
| Inspect capability assurance… | QPushButton | `ModuleInspector._overview_tab` | `self._open_assurance` · [src/angerona/gui/pages.py:4562](../../src/angerona/gui/pages.py#L4562) |
| Generated label or icon | QPushButton | `ModuleInspector._overview_tab` | `self._toggle` · [src/angerona/gui/pages.py:4573](../../src/angerona/gui/pages.py#L4573) |
| Restart module | QPushButton | `ModuleInspector._overview_tab` | `self._restart` · [src/angerona/gui/pages.py:4574](../../src/angerona/gui/pages.py#L4574) |
| Run self-test | QPushButton | `ModuleInspector._overview_tab` | `self._selftest` · [src/angerona/gui/pages.py:4575](../../src/angerona/gui/pages.py#L4575) |
| Open source sandbox | QPushButton | `ModuleInspector._overview_tab` | `self._open_in_sandbox` · [src/angerona/gui/pages.py:4580](../../src/angerona/gui/pages.py#L4580) |
| Open every deduction, file path, GitHub line, and red source highlight | QPushButton | `ModuleInspector._assurance_tab` | `self._open_assurance` · [src/angerona/gui/pages.py:4642](../../src/angerona/gui/pages.py#L4642) |
| Copy contract JSON | QPushButton | `ModuleInspector._contract_tab` | `lambda: QGuiApplication.clipboard().setText(self._contract_body.toPlainText())` · [src/angerona/gui/pages.py:4663](../../src/angerona/gui/pages.py#L4663) |
| Open source sandbox | QPushButton | `ModuleInspector._deps_tab` | `self._open_in_sandbox` · [src/angerona/gui/pages.py:4786](../../src/angerona/gui/pages.py#L4786) |
| Open Settings ▸ API Keys | QPushButton | `ModuleInspector._api_keys_tab` | `self._open_api_key_settings` · [src/angerona/gui/pages.py:4891](../../src/angerona/gui/pages.py#L4891) |
| Open full instructions | QPushButton | `ModuleInspector._help_tab` | `self._open_help` · [src/angerona/gui/pages.py:4917](../../src/angerona/gui/pages.py#L4917) |
| Close | QPushButton | `ModuleInspector._open_help` | `dlg.close` · [src/angerona/gui/pages.py:4928](../../src/angerona/gui/pages.py#L4928) |
| Allow | QPushButton | `AlertDetailDialog.__init__` | `self._act_allow` · [src/angerona/gui/pages.py:5665](../../src/angerona/gui/pages.py#L5665) |
| Undo Allow | QPushButton | `AlertDetailDialog.__init__` | `self._act_undo_allow` · [src/angerona/gui/pages.py:5669](../../src/angerona/gui/pages.py#L5669) |
| Block | QPushButton | `AlertDetailDialog.__init__` | `self._act_block` · [src/angerona/gui/pages.py:5672](../../src/angerona/gui/pages.py#L5672) |
| Analyze | QPushButton | `AlertDetailDialog.__init__` | `self._act_analyze` · [src/angerona/gui/pages.py:5676](../../src/angerona/gui/pages.py#L5676) |
| 🔎 Research | QPushButton | `AlertDetailDialog.__init__` | `self._act_research` · [src/angerona/gui/pages.py:5677](../../src/angerona/gui/pages.py#L5677) |
| 📋 Copy | QPushButton | `AlertDetailDialog.__init__` | `self._act_copy` · [src/angerona/gui/pages.py:5678](../../src/angerona/gui/pages.py#L5678) |
| Close | QPushButton | `AlertDetailDialog.__init__` | `self.close` · [src/angerona/gui/pages.py:5690](../../src/angerona/gui/pages.py#L5690) |
| Details | QPushButton | `AlertsPanel.__init__` | `self._toggle_preview` · [src/angerona/gui/pages.py:6045](../../src/angerona/gui/pages.py#L6045) |
| Columns | QPushButton | `AlertsPanel.__init__` | [src/angerona/gui/pages.py:6053](../../src/angerona/gui/pages.py#L6053) |
| Artifact path | QAction | `AlertsPanel.__init__` | `self._update_optional_columns` · [src/angerona/gui/pages.py:6055](../../src/angerona/gui/pages.py#L6055) |
| Inline Allow / Block / Analyze | QAction | `AlertsPanel.__init__` | `self._update_optional_columns` · [src/angerona/gui/pages.py:6060](../../src/angerona/gui/pages.py#L6060) |
| 🛡  Scan Center | QPushButton | `AlertsPanel.__init__` | `lambda _checked=False: self.scan_requested.emit()` · [src/angerona/gui/pages.py:6071](../../src/angerona/gui/pages.py#L6071) |
| Allow | QPushButton | `AlertsPanel._make_allow_btn` | `lambda: self._allow_event(event)` · [src/angerona/gui/pages.py:6275](../../src/angerona/gui/pages.py#L6275) |
| Block | QPushButton | `AlertsPanel._make_block_btn` | `lambda: self._block_event(event)` · [src/angerona/gui/pages.py:6286](../../src/angerona/gui/pages.py#L6286) |
| Analyze | QPushButton | `AlertsPanel._make_analyze_btn` | `lambda: self._analyze_event(event, btn)` · [src/angerona/gui/pages.py:6300](../../src/angerona/gui/pages.py#L6300) |
| Review details | QPushButton | `SoarPanel.__init__` | `self._review_selected` · [src/angerona/gui/pages.py:6980](../../src/angerona/gui/pages.py#L6980) |
| Approve | QPushButton | `SoarPanel.__init__` | `self._approve_selected` · [src/angerona/gui/pages.py:6987](../../src/angerona/gui/pages.py#L6987) |
| Reject / Dismiss | QPushButton | `SoarPanel.__init__` | `self._dismiss_selected` · [src/angerona/gui/pages.py:6997](../../src/angerona/gui/pages.py#L6997) |
| Execute approved containment | QPushButton | `SoarPanel.__init__` | `self._execute_selected` · [src/angerona/gui/pages.py:7005](../../src/angerona/gui/pages.py#L7005) |
| 🤖 Ask AI (selected) | QPushButton | `SoarPanel.__init__` | `self._consult_ai_selected` · [src/angerona/gui/pages.py:7022](../../src/angerona/gui/pages.py#L7022) |
| 🤖 Consult AI on queue | QPushButton | `SoarPanel.__init__` | `self._consult_ai` · [src/angerona/gui/pages.py:7029](../../src/angerona/gui/pages.py#L7029) |
| Archive & clear history | QPushButton | `SoarPanel.__init__` | `self._clear` · [src/angerona/gui/pages.py:7035](../../src/angerona/gui/pages.py#L7035) |
| Restore last clear | QPushButton | `SoarPanel.__init__` | `self._restore_last_clear` · [src/angerona/gui/pages.py:7041](../../src/angerona/gui/pages.py#L7041) |
| Review details | QAction | `SoarPanel._row_context_menu` | [src/angerona/gui/pages.py:7704](../../src/angerona/gui/pages.py#L7704) |
| Approve | QAction | `SoarPanel._row_context_menu` | [src/angerona/gui/pages.py:7705](../../src/angerona/gui/pages.py#L7705) |
| Execute approved containment | QAction | `SoarPanel._row_context_menu` | [src/angerona/gui/pages.py:7706](../../src/angerona/gui/pages.py#L7706) |
| Reject / Dismiss | QAction | `SoarPanel._row_context_menu` | [src/angerona/gui/pages.py:7707](../../src/angerona/gui/pages.py#L7707) |
| 🤖 Ask AI about this alert | QAction | `SoarPanel._row_context_menu` | [src/angerona/gui/pages.py:7708](../../src/angerona/gui/pages.py#L7708) |
| 📋 Copy message | QAction | `SoarPanel._row_context_menu` | [src/angerona/gui/pages.py:7709](../../src/angerona/gui/pages.py#L7709) |
| Pause | QPushButton | `StatusStrip.__init__` | `self._pause_changed` · [src/angerona/gui/pages.py:8111](../../src/angerona/gui/pages.py#L8111) |
| 🎓 Flight Instructor Mode — AI coaching narration | QCheckBox | `SharkMonitorDialog.__init__` | [src/angerona/gui/pages.py:8572](../../src/angerona/gui/pages.py#L8572) |
| Close (drill keeps running) | QPushButton | `SharkMonitorDialog.__init__` | `self.hide` · [src/angerona/gui/pages.py:8615](../../src/angerona/gui/pages.py#L8615) |
| AngeronaPatch | QPushButton | `AARDialog.__init__` | `self._open_patch_center` · [src/angerona/gui/pages.py:9007](../../src/angerona/gui/pages.py#L9007) |
| Diagnostics / Explain failures | QPushButton | `AARDialog.__init__` | `self._open_diagnostics` · [src/angerona/gui/pages.py:9012](../../src/angerona/gui/pages.py#L9012) |
| Generated label or icon | QPushButton | `AARDialog.__init__` | `self.refresh` · [src/angerona/gui/pages.py:9024](../../src/angerona/gui/pages.py#L9024) |
| Generated label or icon | QPushButton | `AARDialog.__init__` | `self._attempt_fix` · [src/angerona/gui/pages.py:9031](../../src/angerona/gui/pages.py#L9031) |
| ✓  Test Fix Again | QPushButton | `AARDialog.__init__` | `self._attempt_fix` · [src/angerona/gui/pages.py:9044](../../src/angerona/gui/pages.py#L9044) |
| </>  Open Fix Source | QPushButton | `AARDialog.__init__` | `self._open_fix_source` · [src/angerona/gui/pages.py:9052](../../src/angerona/gui/pages.py#L9052) |
| 🧹  Clean & Close | QPushButton | `AARDialog.__init__` | `self._clean_and_close` · [src/angerona/gui/pages.py:9060](../../src/angerona/gui/pages.py#L9060) |
| Overview | Tab | `SettingsDialog.__init__` | [src/angerona/gui/pages.py:9515](../../src/angerona/gui/pages.py#L9515) |
| Information | Tab | `SettingsDialog.__init__` | [src/angerona/gui/pages.py:9516](../../src/angerona/gui/pages.py#L9516) |
| General | Tab | `SettingsDialog.__init__` | [src/angerona/gui/pages.py:9517](../../src/angerona/gui/pages.py#L9517) |
| System | Tab | `SettingsDialog.__init__` | [src/angerona/gui/pages.py:9518](../../src/angerona/gui/pages.py#L9518) |
| Adversary Combat | Tab | `SettingsDialog.__init__` | [src/angerona/gui/pages.py:9519](../../src/angerona/gui/pages.py#L9519) |
| Enterprise | Tab | `SettingsDialog.__init__` | [src/angerona/gui/pages.py:9520](../../src/angerona/gui/pages.py#L9520) |
| Integrations | Tab | `SettingsDialog.__init__` | [src/angerona/gui/pages.py:9521](../../src/angerona/gui/pages.py#L9521) |
| ARIA | Tab | `SettingsDialog.__init__` | [src/angerona/gui/pages.py:9522](../../src/angerona/gui/pages.py#L9522) |
| Trusted Processes | Tab | `SettingsDialog.__init__` | [src/angerona/gui/pages.py:9523](../../src/angerona/gui/pages.py#L9523) |
| Mobile Integration | Tab | `SettingsDialog.__init__` | [src/angerona/gui/pages.py:9524](../../src/angerona/gui/pages.py#L9524) |
| API Keys | Tab | `SettingsDialog.__init__` | [src/angerona/gui/pages.py:9525](../../src/angerona/gui/pages.py#L9525) |
| Self-Test | Tab | `SettingsDialog.__init__` | [src/angerona/gui/pages.py:9528](../../src/angerona/gui/pages.py#L9528) |
| Restore privacy defaults | QPushButton | `SettingsDialog.__init__` | `self._restore_privacy_defaults` · [src/angerona/gui/pages.py:9537](../../src/angerona/gui/pages.py#L9537) |
| Open Tab Code Sandbox | QPushButton | `SettingsDialog.__init__` | `self._open_current_tab_sandbox` · [src/angerona/gui/pages.py:9546](../../src/angerona/gui/pages.py#L9546) |
| Save | QPushButton | `SettingsDialog.__init__` | `self._save` · [src/angerona/gui/pages.py:9554](../../src/angerona/gui/pages.py#L9554) |
| Cancel | QPushButton | `SettingsDialog.__init__` | `self.close` · [src/angerona/gui/pages.py:9555](../../src/angerona/gui/pages.py#L9555) |
| Take me there | QPushButton | `SettingsDialog._tab_information` | `self._info_navigate` · [src/angerona/gui/pages.py:9930](../../src/angerona/gui/pages.py#L9930) |
| Enable interface motion | QCheckBox | `SettingsDialog._tab_general` | [src/angerona/gui/pages.py:10126](../../src/angerona/gui/pages.py#L10126) |
| Adaptive background scan pacing | QCheckBox | `SettingsDialog._tab_general` | [src/angerona/gui/pages.py:10134](../../src/angerona/gui/pages.py#L10134) |
| Show the holographic Angerona Orb when windows minimize | QCheckBox | `SettingsDialog._tab_general` | [src/angerona/gui/pages.py:10143](../../src/angerona/gui/pages.py#L10143) |
| Run Angerona with administrator privileges | QCheckBox | `SettingsDialog._tab_general` | [src/angerona/gui/pages.py:10158](../../src/angerona/gui/pages.py#L10158) |
| Require signed After-Action Reports (refuse unsigned/forged self-hardening input) | QCheckBox | `SettingsDialog._tab_general` | [src/angerona/gui/pages.py:10178](../../src/angerona/gui/pages.py#L10178) |
| Offload ransomware entropy scanning to worker processes (experimental) | QCheckBox | `SettingsDialog._tab_general` | [src/angerona/gui/pages.py:10187](../../src/angerona/gui/pages.py#L10187) |
| Check now | QPushButton | `SettingsDialog._tab_general` | `self._on_check_updates` · [src/angerona/gui/pages.py:10203](../../src/angerona/gui/pages.py#L10203) |
| Check GitHub for updates once a day while Angerona is open (network) | QCheckBox | `SettingsDialog._tab_general` | `self._on_daily_update_staged` · [src/angerona/gui/pages.py:10207](../../src/angerona/gui/pages.py#L10207) |
| Enable maintained scanner integrations | QCheckBox | `SettingsDialog._tab_general` | [src/angerona/gui/pages.py:10239](../../src/angerona/gui/pages.py#L10239) |
| Prepare the pinned Zero-Breach scanner after the dashboard opens | QCheckBox | `SettingsDialog._tab_general` | [src/angerona/gui/pages.py:10241](../../src/angerona/gui/pages.py#L10241) |
| Allow verified downloads for missing scanner files | QCheckBox | `SettingsDialog._tab_general` | [src/angerona/gui/pages.py:10243](../../src/angerona/gui/pages.py#L10243) |
| Automatically request network lockdown for confirmed breaches | QCheckBox | `SettingsDialog._tab_general` | [src/angerona/gui/pages.py:10269](../../src/angerona/gui/pages.py#L10269) |
| Automatically try verified recovery when source startup fails | QCheckBox | `SettingsDialog._tab_general` | `self._startup_recovery_github_enabled.setEnabled` · [src/angerona/gui/pages.py:10276](../../src/angerona/gui/pages.py#L10276) |
| Allow public GitHub source candidates during startup recovery | QCheckBox | `SettingsDialog._tab_general` | [src/angerona/gui/pages.py:10279](../../src/angerona/gui/pages.py#L10279) |
| Arm Adversary Combat and act automatically on my behalf | QCheckBox | `SettingsDialog._tab_adversary_combat` | [src/angerona/gui/pages.py:10319](../../src/angerona/gui/pages.py#L10319) |
| Block the named remote IP and offending program at Windows Firewall | QCheckBox | `SettingsDialog._tab_adversary_combat` | [src/angerona/gui/pages.py:10377](../../src/angerona/gui/pages.py#L10377) |
| Quarantine the exact file artifact (reversible) | QCheckBox | `SettingsDialog._tab_adversary_combat` | [src/angerona/gui/pages.py:10383](../../src/angerona/gui/pages.py#L10383) |
| Automatically isolate the whole host on critical/correlated attack evidence | QCheckBox | `SettingsDialog._tab_adversary_combat` | [src/angerona/gui/pages.py:10389](../../src/angerona/gui/pages.py#L10389) |
| Keep Smart Deception honeypots active automatically | QCheckBox | `SettingsDialog._tab_adversary_combat` | [src/angerona/gui/pages.py:10395](../../src/angerona/gui/pages.py#L10395) |
| Refresh action history | QPushButton | `SettingsDialog._tab_adversary_combat` | `self._refresh_combat_actions` · [src/angerona/gui/pages.py:10420](../../src/angerona/gui/pages.py#L10420) |
| Undo selected | QPushButton | `SettingsDialog._tab_adversary_combat` | `self._undo_selected_combat_action` · [src/angerona/gui/pages.py:10421](../../src/angerona/gui/pages.py#L10421) |
| Undo all reversible | QPushButton | `SettingsDialog._tab_adversary_combat` | `self._undo_all_combat_actions` · [src/angerona/gui/pages.py:10422](../../src/angerona/gui/pages.py#L10422) |
| Generated label or icon | QCheckBox | `SettingsDialog._tab_system` | [src/angerona/gui/pages.py:10770](../../src/angerona/gui/pages.py#L10770) |
| Enable local MCP server on port | QCheckBox | `SettingsDialog._tab_system` | `self._mcp_port.setEnabled` · [src/angerona/gui/pages.py:10794](../../src/angerona/gui/pages.py#L10794) |
| Start in Chill Mode (network-first, low-resource all-day monitoring) | QCheckBox | `SettingsDialog._tab_system` | [src/angerona/gui/pages.py:10808](../../src/angerona/gui/pages.py#L10808) |
| Confirm & reset USB PIN | QPushButton | `SettingsDialog._tab_system` | `self._reset_usb_pin` · [src/angerona/gui/pages.py:10864](../../src/angerona/gui/pages.py#L10864) |
| Launch the Black Box recorder automatically with Angerona | QCheckBox | `SettingsDialog._tab_system` | [src/angerona/gui/pages.py:10901](../../src/angerona/gui/pages.py#L10901) |
| Collect Windows session security events after restart (read-only) | QCheckBox | `SettingsDialog._tab_system` | [src/angerona/gui/pages.py:10919](../../src/angerona/gui/pages.py#L10919) |
| Inventory current-user Chromium extension manifests after restart | QCheckBox | `SettingsDialog._tab_system` | [src/angerona/gui/pages.py:10926](../../src/angerona/gui/pages.py#L10926) |
| Enable same-user live diagnostic sharing after restart | QCheckBox | `SettingsDialog._tab_system` | [src/angerona/gui/pages.py:10943](../../src/angerona/gui/pages.py#L10943) |
| Refresh connection status | QPushButton | `SettingsDialog._tab_system` | `self._refresh_live_debug_status` · [src/angerona/gui/pages.py:10963](../../src/angerona/gui/pages.py#L10963) |
| Copy AI reader command | QPushButton | `SettingsDialog._tab_system` | `self._copy_live_debug_command` · [src/angerona/gui/pages.py:10965](../../src/angerona/gui/pages.py#L10965) |
| Place hidden honeytokens in my Desktop/Documents/AppData (advanced opt-in) | QCheckBox | `SettingsDialog._tab_system` | [src/angerona/gui/pages.py:10974](../../src/angerona/gui/pages.py#L10974) |
| Enable native eBPF kernel telemetry (Linux + BCC + root only) | QCheckBox | `SettingsDialog._tab_system` | [src/angerona/gui/pages.py:10994](../../src/angerona/gui/pages.py#L10994) |
| Automatically remove old runtime alert archives | QCheckBox | `SettingsDialog._alert_retention_controls` | `widget.setEnabled` · [src/angerona/gui/pages.py:11053](../../src/angerona/gui/pages.py#L11053) |
| Clean archives now | QPushButton | `SettingsDialog._alert_retention_controls` | `self._request_alert_cleanup` · [src/angerona/gui/pages.py:11085](../../src/angerona/gui/pages.py#L11085) |
| Refresh status | QPushButton | `SettingsDialog._alert_retention_controls` | `self._refresh_alert_cleanup` · [src/angerona/gui/pages.py:11089](../../src/angerona/gui/pages.py#L11089) |
| Enable authenticated local fleet service | QCheckBox | `SettingsDialog._tab_enterprise` | [src/angerona/gui/pages.py:11142](../../src/angerona/gui/pages.py#L11142) |
| Refresh assessment | QPushButton | `SettingsDialog._tab_enterprise` | `self._refresh_enterprise_assessment` · [src/angerona/gui/pages.py:11203](../../src/angerona/gui/pages.py#L11203) |
| Build current causal snapshot | QPushButton | `SettingsDialog._tab_enterprise` | `self._refresh_enterprise_causal` · [src/angerona/gui/pages.py:11204](../../src/angerona/gui/pages.py#L11204) |
| Copy fleet API contract | QPushButton | `SettingsDialog._tab_enterprise` | `self._copy_fleet_api_contract` · [src/angerona/gui/pages.py:11205](../../src/angerona/gui/pages.py#L11205) |
| Copy public-safe evidence | QPushButton | `SettingsDialog._tab_enterprise` | `self._copy_enterprise_evidence` · [src/angerona/gui/pages.py:11210](../../src/angerona/gui/pages.py#L11210) |
| Browse… | QPushButton | `SettingsDialog._tab_integrations` | `select_ca_file` · [src/angerona/gui/pages.py:11392](../../src/angerona/gui/pages.py#L11392) |
| I explicitly approve plaintext TCP/UDP export | QCheckBox | `SettingsDialog._tab_integrations` | [src/angerona/gui/pages.py:11415](../../src/angerona/gui/pages.py#L11415) |
| Include raw event summaries instead of privacy-redacted summaries | QCheckBox | `SettingsDialog._tab_integrations` | [src/angerona/gui/pages.py:11421](../../src/angerona/gui/pages.py#L11421) |
| I explicitly approve a non-loopback receiver bind | QCheckBox | `SettingsDialog._tab_integrations` | [src/angerona/gui/pages.py:11479](../../src/angerona/gui/pages.py#L11479) |
| Explain trust and delivery details | QPushButton | `SettingsDialog._tab_integrations` | `self._show_integration_details` · [src/angerona/gui/pages.py:11504](../../src/angerona/gui/pages.py#L11504) |
| Enable ARIA (HUD + local assistant) | QCheckBox | `SettingsDialog._tab_aria` | [src/angerona/gui/pages.py:11550](../../src/angerona/gui/pages.py#L11550) |
| Scale cosmetic/UI work to live load (never throttles detection/response) | QCheckBox | `SettingsDialog._tab_aria` | [src/angerona/gui/pages.py:11568](../../src/angerona/gui/pages.py#L11568) |
| Speak threat narration and accept voice commands ('hey aria') | QCheckBox | `SettingsDialog._tab_aria` | [src/angerona/gui/pages.py:11574](../../src/angerona/gui/pages.py#L11574) |
| Allow ElevenLabs cloud TTS (opt-in egress; else local SAPI/pyttsx3) | QCheckBox | `SettingsDialog._tab_aria` | [src/angerona/gui/pages.py:11577](../../src/angerona/gui/pages.py#L11577) |
| Allow sanitized cloud-AI fallback when local Ollama is offline | QCheckBox | `SettingsDialog._tab_aria` | [src/angerona/gui/pages.py:11580](../../src/angerona/gui/pages.py#L11580) |
| Allow privacy-sanitized live-alert evidence to use cloud AI after local triage | QCheckBox | `SettingsDialog._tab_aria` | [src/angerona/gui/pages.py:11588](../../src/angerona/gui/pages.py#L11588) |
| Download verified offline speech model (39 MB) | QPushButton | `SettingsDialog._tab_aria` | `self._install_voice_model` · [src/angerona/gui/pages.py:11614](../../src/angerona/gui/pages.py#L11614) |
| Remember a short room discussion and allow no-wake follow-up questions | QCheckBox | `SettingsDialog._tab_aria` | [src/angerona/gui/pages.py:11634](../../src/angerona/gui/pages.py#L11634) |
| Always-listen: accept every multi-word utterance without saying ARIA | QCheckBox | `SettingsDialog._tab_aria` | [src/angerona/gui/pages.py:11639](../../src/angerona/gui/pages.py#L11639) |
| Enable camera hand-gesture navigation | QCheckBox | `SettingsDialog._tab_aria` | [src/angerona/gui/pages.py:11658](../../src/angerona/gui/pages.py#L11658) |
| Push CRITICAL posture to a channel | QCheckBox | `SettingsDialog._tab_aria` | [src/angerona/gui/pages.py:11683](../../src/angerona/gui/pages.py#L11683) |
| Scan a mailbox for phishing (read-only IMAP, local scoring) | QCheckBox | `SettingsDialog._tab_aria` | [src/angerona/gui/pages.py:11703](../../src/angerona/gui/pages.py#L11703) |
| Allow headless research fetches (else open vetted lookups in the browser) | QCheckBox | `SettingsDialog._tab_aria` | [src/angerona/gui/pages.py:11741](../../src/angerona/gui/pages.py#L11741) |
| Chat with ARIA from Microsoft Teams (needs an Azure Bot) | QCheckBox | `SettingsDialog._tab_aria` | [src/angerona/gui/pages.py:11749](../../src/angerona/gui/pages.py#L11749) |
| JWT bypass unavailable in saved settings (direct-loopback tests only) | QCheckBox | `SettingsDialog._tab_aria` | [src/angerona/gui/pages.py:11776](../../src/angerona/gui/pages.py#L11776) |
| 🔊  Test voice | QPushButton | `SettingsDialog._tab_aria` | `self._aria_test_voice` · [src/angerona/gui/pages.py:11788](../../src/angerona/gui/pages.py#L11788) |
| ✉  Test email | QPushButton | `SettingsDialog._tab_aria` | `self._aria_test_email` · [src/angerona/gui/pages.py:11789](../../src/angerona/gui/pages.py#L11789) |
| 📣  Test channel push | QPushButton | `SettingsDialog._tab_aria` | `self._aria_test_push` · [src/angerona/gui/pages.py:11790](../../src/angerona/gui/pages.py#L11790) |
| 💬  Test Teams creds | QPushButton | `SettingsDialog._tab_aria` | `self._aria_test_teams` · [src/angerona/gui/pages.py:11791](../../src/angerona/gui/pages.py#L11791) |
| Trust name | QPushButton | `SettingsDialog._tab_trusted_processes` | `self._trust_process_name` · [src/angerona/gui/pages.py:11962](../../src/angerona/gui/pages.py#L11962) |
| Browse executable… | QPushButton | `SettingsDialog._tab_trusted_processes` | `self._browse_trusted_process` · [src/angerona/gui/pages.py:11963](../../src/angerona/gui/pages.py#L11963) |
| Remove selected | QPushButton | `SettingsDialog._tab_trusted_processes` | `self._remove_trusted_process` · [src/angerona/gui/pages.py:11964](../../src/angerona/gui/pages.py#L11964) |
| Learn stable signed executables and suggest them for review | QCheckBox | `SettingsDialog._tab_trusted_processes` | [src/angerona/gui/pages.py:11975](../../src/angerona/gui/pages.py#L11975) |
| Refresh learned candidates | QPushButton | `SettingsDialog._tab_trusted_processes` | `self._refresh_process_baseline` · [src/angerona/gui/pages.py:12002](../../src/angerona/gui/pages.py#L12002) |
| Approve eligible candidate | QPushButton | `SettingsDialog._tab_trusted_processes` | `self._approve_process_baseline` · [src/angerona/gui/pages.py:12003](../../src/angerona/gui/pages.py#L12003) |
| Dismiss for 30 days | QPushButton | `SettingsDialog._tab_trusted_processes` | `self._dismiss_process_baseline` · [src/angerona/gui/pages.py:12004](../../src/angerona/gui/pages.py#L12004) |
| Reset learned state | QPushButton | `SettingsDialog._tab_trusted_processes` | `self._reset_process_baseline` · [src/angerona/gui/pages.py:12005](../../src/angerona/gui/pages.py#L12005) |
| Scan running processes | QPushButton | `SettingsDialog._tab_trusted_processes` | `self._scan_running_processes` · [src/angerona/gui/pages.py:12042](../../src/angerona/gui/pages.py#L12042) |
| Trust selected exact path | QPushButton | `SettingsDialog._tab_trusted_processes` | `self._trust_selected_process` · [src/angerona/gui/pages.py:12043](../../src/angerona/gui/pages.py#L12043) |
| Enable Mobile Response Bridge | QCheckBox | `SettingsDialog._tab_mobile` | `_lock` · [src/angerona/gui/pages.py:12307](../../src/angerona/gui/pages.py#L12307) |
| Browse… | QPushButton | `SettingsDialog._tab_mobile` | `self._browse_signal_cli` · [src/angerona/gui/pages.py:12326](../../src/angerona/gui/pages.py#L12326) |
| Save keys | QPushButton | `SettingsDialog._tab_apikeys` | `lambda: self._save_api_keys(notify=True)` · [src/angerona/gui/pages.py:12436](../../src/angerona/gui/pages.py#L12436) |
| ▲  Up | QPushButton | `SettingsDialog._tab_apikeys` | `lambda: self._move_ai_order(-1)` · [src/angerona/gui/pages.py:12480](../../src/angerona/gui/pages.py#L12480) |
| ▼  Down | QPushButton | `SettingsDialog._tab_apikeys` | `lambda: self._move_ai_order(1)` · [src/angerona/gui/pages.py:12480](../../src/angerona/gui/pages.py#L12480) |

## Patch center

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Refresh report / history | QPushButton | `AngeronaPatchDialog.__init__` | `self.refresh` · [src/angerona/gui/patch_center.py:94](../../src/angerona/gui/patch_center.py#L94) |
| Review selected control | QPushButton | `AngeronaPatchDialog.__init__` | `self._build_plan` · [src/angerona/gui/patch_center.py:95](../../src/angerona/gui/patch_center.py#L95) |
| Apply reviewed control | QPushButton | `AngeronaPatchDialog.__init__` | `self._apply` · [src/angerona/gui/patch_center.py:96](../../src/angerona/gui/patch_center.py#L96) |
| Retest native state | QPushButton | `AngeronaPatchDialog.__init__` | `lambda: self._attempt_action('retest')` · [src/angerona/gui/patch_center.py:97](../../src/angerona/gui/patch_center.py#L97) |
| Review rollback | QPushButton | `AngeronaPatchDialog.__init__` | `lambda: self._attempt_action('rollback')` · [src/angerona/gui/patch_center.py:98](../../src/angerona/gui/patch_center.py#L98) |
| Recover transaction | QPushButton | `AngeronaPatchDialog.__init__` | `lambda: self._attempt_action('recover')` · [src/angerona/gui/patch_center.py:99](../../src/angerona/gui/patch_center.py#L99) |
| Open source sandbox | QPushButton | `AngeronaPatchDialog.__init__` | `self._source` · [src/angerona/gui/patch_center.py:100](../../src/angerona/gui/patch_center.py#L100) |
| Close | QPushButton | `AngeronaPatchDialog.__init__` | `self.close` · [src/angerona/gui/patch_center.py:101](../../src/angerona/gui/patch_center.py#L101) |

## Prevention panel

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Inspect native policy | QPushButton | `PreventionPanel.__init__` | `self._refresh` · [src/angerona/gui/prevention_panel.py:95](../../src/angerona/gui/prevention_panel.py#L95) |
| Stage Logon audit plan | QPushButton | `PreventionPanel.__init__` | `self._prepare` · [src/angerona/gui/prevention_panel.py:96](../../src/angerona/gui/prevention_panel.py#L96) |
| Send approved plan | QPushButton | `PreventionPanel.__init__` | `self._apply` · [src/angerona/gui/prevention_panel.py:97](../../src/angerona/gui/prevention_panel.py#L97) |
| Copy exact plan | QPushButton | `PreventionPanel.__init__` | `self._copy` · [src/angerona/gui/prevention_panel.py:98](../../src/angerona/gui/prevention_panel.py#L98) |
| Stage recovery plan | QPushButton | `PreventionPanel.__init__` | `self._restore` · [src/angerona/gui/prevention_panel.py:110](../../src/angerona/gui/prevention_panel.py#L110) |

## Protection service console

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Refresh status | QPushButton | `ProtectionServiceConsole.__init__` | `lambda: self._request(manual=True)` · [src/angerona/gui/protection_service_console.py:309](../../src/angerona/gui/protection_service_console.py#L309) |
| Close console | QPushButton | `ProtectionServiceConsole.__init__` | `self.close` · [src/angerona/gui/protection_service_console.py:313](../../src/angerona/gui/protection_service_console.py#L313) |
| Run Angerona with administrator privileges | QCheckBox | `ProtectionServiceConsole._elevation_settings` | `self._request_operator_elevation` · [src/angerona/gui/protection_service_console.py:330](../../src/angerona/gui/protection_service_console.py#L330) |

## Recorder integrity controls

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Witness committed recorder history on an independent machine | QCheckBox | `RecorderIntegrityControls.__init__` | [src/angerona/gui/recorder_integrity_controls.py:42](../../src/angerona/gui/recorder_integrity_controls.py#L42) |
| Generated label or icon | QToolButton | `RecorderIntegrityControls.__init__` | `expand` · [src/angerona/gui/recorder_integrity_controls.py:51](../../src/angerona/gui/recorder_integrity_controls.py#L51) |
| Authority and its signing key are administered on another machine | QCheckBox | `RecorderIntegrityControls.__init__` | [src/angerona/gui/recorder_integrity_controls.py:61](../../src/angerona/gui/recorder_integrity_controls.py#L61) |
| Create or show this host's public enrollment key | QPushButton | `RecorderIntegrityControls.__init__` | `self._request_identity` · [src/angerona/gui/recorder_integrity_controls.py:97](../../src/angerona/gui/recorder_integrity_controls.py#L97) |

## Recovery panel

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Enroll public recovery authority | QPushButton | `RecoveryPanel.__init__` | `lambda: self._queue('queue_enroll_recovery_authority', self.signer_id.text().strip(), self.public_key.text().strip())` · [src/angerona/gui/recovery_panel.py:61](../../src/angerona/gui/recovery_panel.py#L61) |
| Import signed evidence | QPushButton | `RecoveryPanel.__init__` | `lambda: self._queue('queue_import_recovery_evidence', self.evidence.text().strip())` · [src/angerona/gui/recovery_panel.py:82](../../src/angerona/gui/recovery_panel.py#L82) |
| Test isolated restore | QPushButton | `RecoveryPanel.__init__` | `self._restore` · [src/angerona/gui/recovery_panel.py:85](../../src/angerona/gui/recovery_panel.py#L85) |
| Recheck actual restored bytes | QPushButton | `RecoveryPanel.__init__` | `self._recheck` · [src/angerona/gui/recovery_panel.py:88](../../src/angerona/gui/recovery_panel.py#L88) |
| Opt in to recurring tests while this guard runs | QCheckBox | `RecoveryPanel.__init__` | [src/angerona/gui/recovery_panel.py:93](../../src/angerona/gui/recovery_panel.py#L93) |
| Apply recurring-test choice | QPushButton | `RecoveryPanel.__init__` | `lambda: self._queue('queue_recovery_schedule', self.recurring.isChecked(), self.interval.value())` · [src/angerona/gui/recovery_panel.py:100](../../src/angerona/gui/recovery_panel.py#L100) |
| Choose… | QPushButton | `RecoveryPanel._path_row` | `select` · [src/angerona/gui/recovery_panel.py:136](../../src/angerona/gui/recovery_panel.py#L136) |

## Red team app

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Close | QPushButton | `_run_qt.Host.receive` | `view.close` · [src/angerona/gui/red_team_app.py:356](../../src/angerona/gui/red_team_app.py#L356) |

## Red team bridge

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Retry tool | QPushButton | `RedTeamBridge._review_startup_failure.build` | `lambda: self._retry_startup_owner(window._startup_owner)` · [src/angerona/gui/red_team_bridge.py:1411](../../src/angerona/gui/red_team_bridge.py#L1411) |
| Close | QPushButton | `RedTeamBridge._review_startup_failure.build` | `window.close` · [src/angerona/gui/red_team_bridge.py:1413](../../src/angerona/gui/red_team_bridge.py#L1413) |

## Red team console

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| ▶  Run | Tab | `RedTeamConsole.__init__` | [src/angerona/gui/red_team_console.py:500](../../src/angerona/gui/red_team_console.py#L500) |
| 🕑  History | Tab | `RedTeamConsole.__init__` | [src/angerona/gui/red_team_console.py:501](../../src/angerona/gui/red_team_console.py#L501) |
| 🛰  Device Security Lab | Tab | `RedTeamConsole.__init__` | [src/angerona/gui/red_team_console.py:502](../../src/angerona/gui/red_team_console.py#L502) |
| 🧪  Sandbox Editor | Tab | `RedTeamConsole.__init__` | [src/angerona/gui/red_team_console.py:503](../../src/angerona/gui/red_team_console.py#L503) |
| GitHub Tools | Tab | `RedTeamConsole.__init__` | [src/angerona/gui/red_team_console.py:506](../../src/angerona/gui/red_team_console.py#L506) |
| Shark — noisy commodity-malware chain | QCheckBox | `RedTeamConsole._build_run_tab` | [src/angerona/gui/red_team_console.py:683](../../src/angerona/gui/red_team_console.py#L683) |
| APT Red Team — quiet adversary campaign | QCheckBox | `RedTeamConsole._build_run_tab` | [src/angerona/gui/red_team_console.py:687](../../src/angerona/gui/red_team_console.py#L687) |
| Comprehensive safe catalog — 37 authenticated detector contracts | QCheckBox | `RedTeamConsole._build_run_tab` | [src/angerona/gui/red_team_console.py:695](../../src/angerona/gui/red_team_console.py#L695) |
| Campaign mode — follow kill-chain order | QCheckBox | `RedTeamConsole._build_run_tab` | [src/angerona/gui/red_team_console.py:721](../../src/angerona/gui/red_team_console.py#L721) |
| Browse… | QPushButton | `RedTeamConsole._build_run_tab` | `self._browse` · [src/angerona/gui/red_team_console.py:753](../../src/angerona/gui/red_team_console.py#L753) |
| Analogy coaching (Flight Instructor) — explain each step in plain English while it runs | QCheckBox | `RedTeamConsole._build_run_tab` | [src/angerona/gui/red_team_console.py:782](../../src/angerona/gui/red_team_console.py#L782) |
| Auto-contain detected markers during the run | QCheckBox | `RedTeamConsole._build_run_tab` | [src/angerona/gui/red_team_console.py:786](../../src/angerona/gui/red_team_console.py#L786) |
| Refresh containment readiness | QPushButton | `RedTeamConsole._build_run_tab` | `self._refresh_response_readiness` · [src/angerona/gui/red_team_console.py:807](../../src/angerona/gui/red_team_console.py#L807) |
| ▶  Launch simulation | QPushButton | `RedTeamConsole._build_run_tab` | `self._launch` · [src/angerona/gui/red_team_console.py:925](../../src/angerona/gui/red_team_console.py#L925) |
| ■  Stop & clean | QPushButton | `RedTeamConsole._build_run_tab` | `self._stop` · [src/angerona/gui/red_team_console.py:929](../../src/angerona/gui/red_team_console.py#L929) |
| ↻ Refresh | QPushButton | `RedTeamConsole._build_history_tab` | `self._load_history` · [src/angerona/gui/red_team_console.py:1656](../../src/angerona/gui/red_team_console.py#L1656) |
| 📂 Open folder | QPushButton | `RedTeamConsole._build_history_tab` | `self._open_history_folder` · [src/angerona/gui/red_team_console.py:1657](../../src/angerona/gui/red_team_console.py#L1657) |
| I own this device or have explicit permission to assess it | QCheckBox | `RedTeamConsole._build_device_lab_tab` | [src/angerona/gui/red_team_console.py:1877](../../src/angerona/gui/red_team_console.py#L1877) |
| Generated label or icon | QCheckBox | `RedTeamConsole._build_device_lab_tab` | [src/angerona/gui/red_team_console.py:1891](../../src/angerona/gui/red_team_console.py#L1891) |
| ➕  Create enrollment | QPushButton | `RedTeamConsole._build_device_lab_tab` | `self._create_device_enrollment` · [src/angerona/gui/red_team_console.py:1898](../../src/angerona/gui/red_team_console.py#L1898) |
| ↻  Refresh | QPushButton | `RedTeamConsole._build_device_lab_tab` | `self._refresh_device_enrollments` · [src/angerona/gui/red_team_console.py:1900](../../src/angerona/gui/red_team_console.py#L1900) |
| 🔐  Confirm companion | QPushButton | `RedTeamConsole._build_device_lab_tab` | `self._confirm_device_enrollment` · [src/angerona/gui/red_team_console.py:1921](../../src/angerona/gui/red_team_console.py#L1921) |
| 📤  Export challenge | QPushButton | `RedTeamConsole._build_device_lab_tab` | `self._export_device_challenge` · [src/angerona/gui/red_team_console.py:1923](../../src/angerona/gui/red_team_console.py#L1923) |
| 📥  Import response | QPushButton | `RedTeamConsole._build_device_lab_tab` | `self._import_device_pairing_response` · [src/angerona/gui/red_team_console.py:1925](../../src/angerona/gui/red_team_console.py#L1925) |
| 🖥  Inspect this computer | QPushButton | `RedTeamConsole._build_device_lab_tab` | `self._inspect_local_device` · [src/angerona/gui/red_team_console.py:1962](../../src/angerona/gui/red_team_console.py#L1962) |
| 📥  Import signed device report | QPushButton | `RedTeamConsole._build_device_lab_tab` | `self._import_device_evidence` · [src/angerona/gui/red_team_console.py:1964](../../src/angerona/gui/red_team_console.py#L1964) |
| 📤  Export findings | QPushButton | `RedTeamConsole._build_device_lab_tab` | `self._export_device_report` · [src/angerona/gui/red_team_console.py:1966](../../src/angerona/gui/red_team_console.py#L1966) |
| 💾  Save working copy | QPushButton | `RedTeamConsole._build_editor_tab` | `self._save_editor` · [src/angerona/gui/red_team_console.py:2289](../../src/angerona/gui/red_team_console.py#L2289) |
| ↻  Reload saved copy | QPushButton | `RedTeamConsole._build_editor_tab` | `self._reload_editor` · [src/angerona/gui/red_team_console.py:2291](../../src/angerona/gui/red_team_console.py#L2291) |
| ↩  Roll back copy | QPushButton | `RedTeamConsole._build_editor_tab` | `self._rollback_editor` · [src/angerona/gui/red_team_console.py:2293](../../src/angerona/gui/red_team_console.py#L2293) |
| Close | QPushButton | `RedTeamConsole._open_stage_detail` | `dialog.close` · [src/angerona/gui/red_team_console.py:2445](../../src/angerona/gui/red_team_console.py#L2445) |

## Resolve center

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| ‹ Previous | QPushButton | `ResolveCenter.__init__` | `lambda: self._change_page(-1)` · [src/angerona/gui/resolve_center.py:210](../../src/angerona/gui/resolve_center.py#L210) |
| Next › | QPushButton | `ResolveCenter.__init__` | `lambda: self._change_page(1)` · [src/angerona/gui/resolve_center.py:217](../../src/angerona/gui/resolve_center.py#L217) |
| Detail | QPushButton | `ResolveCenter.__init__` | `lambda: self._act_selected(self._detail)` · [src/angerona/gui/resolve_center.py:221](../../src/angerona/gui/resolve_center.py#L221) |
| Allow | QPushButton | `ResolveCenter.__init__` | `lambda: self._act_selected(self._allow)` · [src/angerona/gui/resolve_center.py:223](../../src/angerona/gui/resolve_center.py#L223) |
| Block | QPushButton | `ResolveCenter.__init__` | `lambda: self._act_selected(self._block)` · [src/angerona/gui/resolve_center.py:226](../../src/angerona/gui/resolve_center.py#L226) |
| Ignore | QPushButton | `ResolveCenter.__init__` | `lambda: self._act_selected(self._ignore)` · [src/angerona/gui/resolve_center.py:228](../../src/angerona/gui/resolve_center.py#L228) |
| 🔕  Ignore all active | QPushButton | `ResolveCenter.__init__` | `self._ignore_all_shown` · [src/angerona/gui/resolve_center.py:230](../../src/angerona/gui/resolve_center.py#L230) |
| Ignored… | QPushButton | `ResolveCenter.__init__` | `self._show_ignored` · [src/angerona/gui/resolve_center.py:236](../../src/angerona/gui/resolve_center.py#L236) |
| Refresh | QPushButton | `ResolveCenter.__init__` | `self._reload` · [src/angerona/gui/resolve_center.py:239](../../src/angerona/gui/resolve_center.py#L239) |
| Close | QPushButton | `ResolveCenter.__init__` | `self.close` · [src/angerona/gui/resolve_center.py:240](../../src/angerona/gui/resolve_center.py#L240) |
| Generated label or icon | QPushButton | `ResolveCenter._btn` | `slot` · [src/angerona/gui/resolve_center.py:437](../../src/angerona/gui/resolve_center.py#L437) |
| Close | QPushButton | `ResolveCenter._show_ignored` | `dlg.close` · [src/angerona/gui/resolve_center.py:512](../../src/angerona/gui/resolve_center.py#L512) |

## Response status

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Refresh response status | QPushButton | `ResponseStatusPanel.__init__` | `self.refresh` · [src/angerona/gui/response_status.py:78](../../src/angerona/gui/response_status.py#L78) |

## Rules playbooks

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Runtime settings | QPushButton | `RulesPlaybooksPanel.__init__` | `lambda _checked=False: open_settings()` · [src/angerona/gui/rules_playbooks.py:114](../../src/angerona/gui/rules_playbooks.py#L114) |
| Fetch catalog | QPushButton | `RulesPlaybooksPanel.__init__` | `self._discover` · [src/angerona/gui/rules_playbooks.py:137](../../src/angerona/gui/rules_playbooks.py#L137) |
| Review source | QPushButton | `RulesPlaybooksPanel.__init__` | `lambda: self._open_source_review() if callable(self._open_source_review) else None` · [src/angerona/gui/rules_playbooks.py:138](../../src/angerona/gui/rules_playbooks.py#L138) |
| Select compatible | QPushButton | `RulesPlaybooksPanel.__init__` | `lambda: self._check_candidates(True)` · [src/angerona/gui/rules_playbooks.py:154](../../src/angerona/gui/rules_playbooks.py#L154) |
| Clear selection | QPushButton | `RulesPlaybooksPanel.__init__` | `lambda: self._check_candidates(False)` · [src/angerona/gui/rules_playbooks.py:155](../../src/angerona/gui/rules_playbooks.py#L155) |
| Install checked | QPushButton | `RulesPlaybooksPanel.__init__` | `self._install` · [src/angerona/gui/rules_playbooks.py:156](../../src/angerona/gui/rules_playbooks.py#L156) |
| Sources | Tab | `RulesPlaybooksPanel.__init__` | [src/angerona/gui/rules_playbooks.py:164](../../src/angerona/gui/rules_playbooks.py#L164) |
| Create draft | QPushButton | `RulesPlaybooksPanel.__init__` | `self._create` · [src/angerona/gui/rules_playbooks.py:174](../../src/angerona/gui/rules_playbooks.py#L174) |
| Save draft | QPushButton | `RulesPlaybooksPanel.__init__` | `self._save` · [src/angerona/gui/rules_playbooks.py:202](../../src/angerona/gui/rules_playbooks.py#L202) |
| Validate | QPushButton | `RulesPlaybooksPanel.__init__` | [src/angerona/gui/rules_playbooks.py:203](../../src/angerona/gui/rules_playbooks.py#L203) |
| Sample test | QPushButton | `RulesPlaybooksPanel.__init__` | [src/angerona/gui/rules_playbooks.py:204](../../src/angerona/gui/rules_playbooks.py#L204) |
| Diff | QPushButton | `RulesPlaybooksPanel.__init__` | [src/angerona/gui/rules_playbooks.py:205](../../src/angerona/gui/rules_playbooks.py#L205) |
| Activate validated | QPushButton | `RulesPlaybooksPanel.__init__` | [src/angerona/gui/rules_playbooks.py:206](../../src/angerona/gui/rules_playbooks.py#L206) |
| Disable | QPushButton | `RulesPlaybooksPanel.__init__` | [src/angerona/gui/rules_playbooks.py:207](../../src/angerona/gui/rules_playbooks.py#L207) |
| Rollback | QPushButton | `RulesPlaybooksPanel.__init__` | [src/angerona/gui/rules_playbooks.py:208](../../src/angerona/gui/rules_playbooks.py#L208) |
| Drafts | Tab | `RulesPlaybooksPanel.__init__` | [src/angerona/gui/rules_playbooks.py:213](../../src/angerona/gui/rules_playbooks.py#L213) |
| Tests & records | Tab | `RulesPlaybooksPanel.__init__` | [src/angerona/gui/rules_playbooks.py:227](../../src/angerona/gui/rules_playbooks.py#L227) |
| Refresh | QPushButton | `RulesPlaybooksPanel.__init__` | `self.refresh` · [src/angerona/gui/rules_playbooks.py:232](../../src/angerona/gui/rules_playbooks.py#L232) |
| Credits / licenses | QPushButton | `RulesPlaybooksPanel.__init__` | `lambda: self._start('credits', lambda _op, _progress: library.credits())` · [src/angerona/gui/rules_playbooks.py:233](../../src/angerona/gui/rules_playbooks.py#L233) |
| DetectionForge | QPushButton | `RulesPlaybooksPanel.__init__` | `lambda: self._open_forge() if callable(self._open_forge) else None` · [src/angerona/gui/rules_playbooks.py:234](../../src/angerona/gui/rules_playbooks.py#L234) |
| Cancel action | QPushButton | `RulesPlaybooksPanel.__init__` | `self.cancel` · [src/angerona/gui/rules_playbooks.py:236](../../src/angerona/gui/rules_playbooks.py#L236) |
| Preview JSON in technical editor | QPushButton | `RulesPlaybooksPanel._build_strategy` | `self._preview_strategy` · [src/angerona/gui/rules_playbooks.py:321](../../src/angerona/gui/rules_playbooks.py#L321) |
| Create guided SOAR draft | QPushButton | `RulesPlaybooksPanel._build_strategy` | `self._create_strategy` · [src/angerona/gui/rules_playbooks.py:322](../../src/angerona/gui/rules_playbooks.py#L322) |
| Generated label or icon | QToolButton | `RulesPlaybooksPanel._build_strategy` | `self.definitions.setVisible` · [src/angerona/gui/rules_playbooks.py:326](../../src/angerona/gui/rules_playbooks.py#L326) |

## Sandbox editor

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Close | QPushButton | `HistoryDialog.__init__` | `self.close` · [src/angerona/gui/sandbox_editor.py:166](../../src/angerona/gui/sandbox_editor.py#L166) |
| Next | QPushButton | `SandboxEditor._build_ui` | `lambda: self._find_next(True)` · [src/angerona/gui/sandbox_editor.py:265](../../src/angerona/gui/sandbox_editor.py#L265) |
| Prev | QPushButton | `SandboxEditor._build_ui` | `lambda: self._find_next(False)` · [src/angerona/gui/sandbox_editor.py:265](../../src/angerona/gui/sandbox_editor.py#L265) |
| Generated label or icon | QPushButton | `SandboxEditor._build_ui` | `slot` · [src/angerona/gui/sandbox_editor.py:303](../../src/angerona/gui/sandbox_editor.py#L303) |
| Exit Sandbox | QPushButton | `SandboxEditor._build_ui` | `self.close` · [src/angerona/gui/sandbox_editor.py:307](../../src/angerona/gui/sandbox_editor.py#L307) |

## Scan center

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Browse… | QPushButton | `ScanCenterPanel.__init__` | `self._browse` · [src/angerona/gui/scan_center.py:108](../../src/angerona/gui/scan_center.py#L108) |
| Also request a Microsoft Defender custom scan (Windows only) | QCheckBox | `ScanCenterPanel.__init__` | [src/angerona/gui/scan_center.py:112](../../src/angerona/gui/scan_center.py#L112) |
| 📁  Scan selected folder / drive | QPushButton | `ScanCenterPanel.__init__` | `self._scan_selected_path` · [src/angerona/gui/scan_center.py:124](../../src/angerona/gui/scan_center.py#L124) |
| ⚡  Microsoft Defender quick scan | QPushButton | `ScanCenterPanel.__init__` | `self._defender_quick_scan` · [src/angerona/gui/scan_center.py:126](../../src/angerona/gui/scan_center.py#L126) |
| 🎐  Audit local listening ports | QPushButton | `ScanCenterPanel.__init__` | `self._audit_ports` · [src/angerona/gui/scan_center.py:128](../../src/angerona/gui/scan_center.py#L128) |
| 📡  Review local network posture | QPushButton | `ScanCenterPanel.__init__` | `self._audit_network` · [src/angerona/gui/scan_center.py:130](../../src/angerona/gui/scan_center.py#L130) |
| ■  Stop scan | QPushButton | `ScanCenterPanel.__init__` | `self._cancel` · [src/angerona/gui/scan_center.py:132](../../src/angerona/gui/scan_center.py#L132) |
| 📤  Export report | QPushButton | `ScanCenterPanel.__init__` | `self._export` · [src/angerona/gui/scan_center.py:203](../../src/angerona/gui/scan_center.py#L203) |

## Selftest results

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Generated label | Tab | `SelfTestResultsDialog.__init__` | [src/angerona/gui/selftest_results.py:90](../../src/angerona/gui/selftest_results.py#L90) |
| Open module details | QPushButton | `SelfTestResultsDialog.__init__` | `lambda: self.module_requested.emit(self.modules.currentData())` · [src/angerona/gui/selftest_results.py:99](../../src/angerona/gui/selftest_results.py#L99) |
| Test selected module | QPushButton | `SelfTestResultsDialog.__init__` | `self._retry_module` · [src/angerona/gui/selftest_results.py:101](../../src/angerona/gui/selftest_results.py#L101) |
| Recover selected worker | QPushButton | `SelfTestResultsDialog.__init__` | `self._restart_module` · [src/angerona/gui/selftest_results.py:103](../../src/angerona/gui/selftest_results.py#L103) |
| Module checks | Tab | `SelfTestResultsDialog.__init__` | [src/angerona/gui/selftest_results.py:113](../../src/angerona/gui/selftest_results.py#L113) |
| Full report | Tab | `SelfTestResultsDialog.__init__` | [src/angerona/gui/selftest_results.py:117](../../src/angerona/gui/selftest_results.py#L117) |
| I approve recovery for the eligible workers listed in this report. | QCheckBox | `SelfTestResultsDialog.__init__` | `self._update_module_controls` · [src/angerona/gui/selftest_results.py:122](../../src/angerona/gui/selftest_results.py#L122) |
| Copy report | QPushButton | `SelfTestResultsDialog.__init__` | `lambda: QApplication.clipboard().setText(self._report)` · [src/angerona/gui/selftest_results.py:127](../../src/angerona/gui/selftest_results.py#L127) |
| Restart approved modules | QPushButton | `SelfTestResultsDialog.__init__` | `self._restart` · [src/angerona/gui/selftest_results.py:129](../../src/angerona/gui/selftest_results.py#L129) |
| Run self-test again | QPushButton | `SelfTestResultsDialog.__init__` | `self._retry` · [src/angerona/gui/selftest_results.py:135](../../src/angerona/gui/selftest_results.py#L135) |
| Close | QPushButton | `SelfTestResultsDialog.__init__` | `self.close` · [src/angerona/gui/selftest_results.py:137](../../src/angerona/gui/selftest_results.py#L137) |

## Selftest settings

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Run selected test | QPushButton | `SelfTestSettingsPanel.__init__` | `lambda: self._start([self.modules.currentText()])` · [src/angerona/gui/selftest_settings.py:59](../../src/angerona/gui/selftest_settings.py#L59) |
| Run all tests | QPushButton | `SelfTestSettingsPanel.__init__` | `lambda: self._start(None)` · [src/angerona/gui/selftest_settings.py:62](../../src/angerona/gui/selftest_settings.py#L62) |
| Automatically recover this module after a confirmed worker fault | QCheckBox | `SelfTestSettingsPanel.__init__` | `self._set_recovery` · [src/angerona/gui/selftest_settings.py:82](../../src/angerona/gui/selftest_settings.py#L82) |
| View test code | QPushButton | `SelfTestSettingsPanel.__init__` | `self._show_source` · [src/angerona/gui/selftest_settings.py:89](../../src/angerona/gui/selftest_settings.py#L89) |
| Edit sandbox copy | QPushButton | `SelfTestSettingsPanel.__init__` | `self._open_sandbox` · [src/angerona/gui/selftest_settings.py:91](../../src/angerona/gui/selftest_settings.py#L91) |
| Open repository source | QPushButton | `SelfTestSettingsPanel.__init__` | `self._open_repository` · [src/angerona/gui/selftest_settings.py:93](../../src/angerona/gui/selftest_settings.py#L93) |

## Sentinel lens

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Import local logs… | QPushButton | `SentinelLensDialog.__init__` | `self._import_logs` · [src/angerona/gui/sentinel_lens.py:271](../../src/angerona/gui/sentinel_lens.py#L271) |
| Refresh graph | QPushButton | `SentinelLensDialog.__init__` | `lambda: self.refresh(force=True, user_requested=True)` · [src/angerona/gui/sentinel_lens.py:273](../../src/angerona/gui/sentinel_lens.py#L273) |
| Fit graph | QPushButton | `SentinelLensDialog.__init__` | `self._fit` · [src/angerona/gui/sentinel_lens.py:275](../../src/angerona/gui/sentinel_lens.py#L275) |
| Explain selection with strict loopback local AI | QPushButton | `SentinelLensDialog.__init__` | `self._ask_local_ai` · [src/angerona/gui/sentinel_lens.py:312](../../src/angerona/gui/sentinel_lens.py#L312) |
| Close | QPushButton | `SentinelLensDialog.__init__` | `self.close` · [src/angerona/gui/sentinel_lens.py:351](../../src/angerona/gui/sentinel_lens.py#L351) |

## Setup wizard

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| ← Back | QPushButton | `SetupWizard.__init__` | `lambda: self._go(-1)` · [src/angerona/gui/setup_wizard.py:1168](../../src/angerona/gui/setup_wizard.py#L1168) |
| Skip | QPushButton | `SetupWizard.__init__` | `lambda: self._go(+1)` · [src/angerona/gui/setup_wizard.py:1169](../../src/angerona/gui/setup_wizard.py#L1169) |
| Next → | QPushButton | `SetupWizard.__init__` | `lambda: self._go(+1)` · [src/angerona/gui/setup_wizard.py:1170](../../src/angerona/gui/setup_wizard.py#L1170) |
| Generated label or icon | QCheckBox | `SetupWizard._make_field` | [src/angerona/gui/setup_wizard.py:1227](../../src/angerona/gui/setup_wizard.py#L1227) |
| Generated label or icon | QPushButton | `SetupWizard._make_field` | `lambda _checked=False, action=field.key: self._do_action(action)` · [src/angerona/gui/setup_wizard.py:1307](../../src/angerona/gui/setup_wizard.py#L1307) |

## Simulation diagnostics

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Refresh verified report | QPushButton | `SimulationDiagnosticsPanel.__init__` | `self.refresh_diagnostics` · [src/angerona/gui/simulation_diagnostics.py:289](../../src/angerona/gui/simulation_diagnostics.py#L289) |
| Copy full diagnostics JSON | QPushButton | `SimulationDiagnosticsPanel.__init__` | `self.copy_json` · [src/angerona/gui/simulation_diagnostics.py:318](../../src/angerona/gui/simulation_diagnostics.py#L318) |
| Export full JSON… | QPushButton | `SimulationDiagnosticsPanel.__init__` | `self.export_json` · [src/angerona/gui/simulation_diagnostics.py:321](../../src/angerona/gui/simulation_diagnostics.py#L321) |
| Open fix review… | QPushButton | `SimulationDiagnosticsPanel.__init__` | `self.review_selected_fix` · [src/angerona/gui/simulation_diagnostics.py:324](../../src/angerona/gui/simulation_diagnostics.py#L324) |
| Close | QPushButton | `SimulationDiagnosticsPanel.__init__` | `self.close` · [src/angerona/gui/simulation_diagnostics.py:328](../../src/angerona/gui/simulation_diagnostics.py#L328) |

## Spyware guard page

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Spyware Scan | QPushButton | `SpywareGuardPage.__init__` | `self._request_scan` · [src/angerona/gui/spyware_guard_page.py:251](../../src/angerona/gui/spyware_guard_page.py#L251) |
| Zero-Breach | Tab | `SpywareGuardPage.__init__` | [src/angerona/gui/spyware_guard_page.py:277](../../src/angerona/gui/spyware_guard_page.py#L277) |
| News offline · enable research network access in Policy / Beacon. | QPushButton | `SpywareGuardPage._build_news_strip` | `self._open_news_details` · [src/angerona/gui/spyware_guard_page.py:320](../../src/angerona/gui/spyware_guard_page.py#L320) |
| Generated label or icon | QPushButton | `SpywareGuardPage._build_news_strip` | `self._open_news_article` · [src/angerona/gui/spyware_guard_page.py:334](../../src/angerona/gui/spyware_guard_page.py#L334) |
| Pause | QPushButton | `SpywareGuardPage._build_news_strip` | `self._pause_news` · [src/angerona/gui/spyware_guard_page.py:340](../../src/angerona/gui/spyware_guard_page.py#L340) |
| Refresh | QPushButton | `SpywareGuardPage._build_news_strip` | `self._request_news_refresh` · [src/angerona/gui/spyware_guard_page.py:347](../../src/angerona/gui/spyware_guard_page.py#L347) |
| News settings | QPushButton | `SpywareGuardPage._build_news_strip` | `self._open_news_settings` · [src/angerona/gui/spyware_guard_page.py:353](../../src/angerona/gui/spyware_guard_page.py#L353) |
| Feed details | QPushButton | `SpywareGuardPage._build_news_strip` | `feed_details.setVisible` · [src/angerona/gui/spyware_guard_page.py:366](../../src/angerona/gui/spyware_guard_page.py#L366) |
| Open source in browser | QPushButton | `SpywareGuardPage._open_news_details` | `lambda: self._open_news_url(source_button.property('news_item'))` · [src/angerona/gui/spyware_guard_page.py:651](../../src/angerona/gui/spyware_guard_page.py#L651) |
| Close | QPushButton | `SpywareGuardPage._open_news_details` | `dialog.close` · [src/angerona/gui/spyware_guard_page.py:654](../../src/angerona/gui/spyware_guard_page.py#L654) |
| Recent hits | Tab | `SpywareGuardPage._build_dashboard` | [src/angerona/gui/spyware_guard_page.py:698](../../src/angerona/gui/spyware_guard_page.py#L698) |
| Isolations / response | Tab | `SpywareGuardPage._build_dashboard` | [src/angerona/gui/spyware_guard_page.py:699](../../src/angerona/gui/spyware_guard_page.py#L699) |
| Coverage | Tab | `SpywareGuardPage._build_dashboard` | [src/angerona/gui/spyware_guard_page.py:704](../../src/angerona/gui/spyware_guard_page.py#L704) |
| Dashboard | Tab | `SpywareGuardPage._build_dashboard` | [src/angerona/gui/spyware_guard_page.py:713](../../src/angerona/gui/spyware_guard_page.py#L713) |
| Import definitions… | QPushButton | `SpywareGuardPage._build_definitions` | `self._import_definitions` · [src/angerona/gui/spyware_guard_page.py:736](../../src/angerona/gui/spyware_guard_page.py#L736) |
| Activate imported pack | QPushButton | `SpywareGuardPage._build_definitions` | `self._activate_definitions` · [src/angerona/gui/spyware_guard_page.py:737](../../src/angerona/gui/spyware_guard_page.py#L737) |
| Roll back to previous pack | QPushButton | `SpywareGuardPage._build_definitions` | `self._rollback_definitions` · [src/angerona/gui/spyware_guard_page.py:738](../../src/angerona/gui/spyware_guard_page.py#L738) |
| Definitions | Tab | `SpywareGuardPage._build_definitions` | [src/angerona/gui/spyware_guard_page.py:752](../../src/angerona/gui/spyware_guard_page.py#L752) |
| Generated label or icon | QCheckBox | `SpywareGuardPage._build_settings` | `self._mark_settings_dirty` · [src/angerona/gui/spyware_guard_page.py:851](../../src/angerona/gui/spyware_guard_page.py#L851) |
| Configure notification channel… | QPushButton | `SpywareGuardPage._build_settings` | `lambda: self.settings_requested.emit('Integrations')` · [src/angerona/gui/spyware_guard_page.py:872](../../src/angerona/gui/spyware_guard_page.py#L872) |
| Configure Signal destination… | QPushButton | `SpywareGuardPage._build_settings` | `lambda: self.settings_requested.emit('Mobile Integration')` · [src/angerona/gui/spyware_guard_page.py:874](../../src/angerona/gui/spyware_guard_page.py#L874) |
| Apply SpywareGuard settings | QPushButton | `SpywareGuardPage._build_settings` | `self._save_settings` · [src/angerona/gui/spyware_guard_page.py:880](../../src/angerona/gui/spyware_guard_page.py#L880) |
| Policy / Beacon | Tab | `SpywareGuardPage._build_settings` | [src/angerona/gui/spyware_guard_page.py:884](../../src/angerona/gui/spyware_guard_page.py#L884) |
| Fetch & extract | QPushButton | `SpywareGuardPage._build_research` | `self._queue_report` · [src/angerona/gui/spyware_guard_page.py:898](../../src/angerona/gui/spyware_guard_page.py#L898) |
| Research sources | Tab | `SpywareGuardPage._build_research` | [src/angerona/gui/spyware_guard_page.py:906](../../src/angerona/gui/spyware_guard_page.py#L906) |
| Extracted indicators | Tab | `SpywareGuardPage._build_research` | [src/angerona/gui/spyware_guard_page.py:907](../../src/angerona/gui/spyware_guard_page.py#L907) |
| Approve selected indicator | QPushButton | `SpywareGuardPage._build_research` | `lambda: self._review_indicator(True)` · [src/angerona/gui/spyware_guard_page.py:909](../../src/angerona/gui/spyware_guard_page.py#L909) |
| Deactivate selected indicator | QPushButton | `SpywareGuardPage._build_research` | `lambda: self._review_indicator(False)` · [src/angerona/gui/spyware_guard_page.py:910](../../src/angerona/gui/spyware_guard_page.py#L910) |
| Stage YARA / Sigma / NDR candidates | QPushButton | `SpywareGuardPage._build_research` | `self._queue_rule_export` · [src/angerona/gui/spyware_guard_page.py:914](../../src/angerona/gui/spyware_guard_page.py#L914) |
| Research / Rules | Tab | `SpywareGuardPage._build_research` | [src/angerona/gui/spyware_guard_page.py:918](../../src/angerona/gui/spyware_guard_page.py#L918) |
| Run offline rehearsal | QPushButton | `SpywareGuardPage._build_sandbox` | `self._run_sandbox` · [src/angerona/gui/spyware_guard_page.py:934](../../src/angerona/gui/spyware_guard_page.py#L934) |
| Open source Analysis Lab… | QPushButton | `SpywareGuardPage._build_sandbox` | `self._open_analysis_lab` · [src/angerona/gui/spyware_guard_page.py:942](../../src/angerona/gui/spyware_guard_page.py#L942) |
| Sandbox | Tab | `SpywareGuardPage._build_sandbox` | [src/angerona/gui/spyware_guard_page.py:949](../../src/angerona/gui/spyware_guard_page.py#L949) |
| Open primary research source in browser | QPushButton | `SpywareGuardPage._build_guide` | `self._open_guide_source` · [src/angerona/gui/spyware_guard_page.py:964](../../src/angerona/gui/spyware_guard_page.py#L964) |
| Field Guide | Tab | `SpywareGuardPage._build_guide` | [src/angerona/gui/spyware_guard_page.py:968](../../src/angerona/gui/spyware_guard_page.py#L968) |

## Storage controls

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Allow bounded recovery copies | QCheckBox | `StorageControls.__init__` | [src/angerona/gui/storage_controls.py:195](../../src/angerona/gui/storage_controls.py#L195) |
| Also request automatic Windows shadow copies (advanced) | QCheckBox | `StorageControls.__init__` | [src/angerona/gui/storage_controls.py:212](../../src/angerona/gui/storage_controls.py#L212) |
| Block new recovery data | QPushButton | `StorageControls.__init__` | `self._block` · [src/angerona/gui/storage_controls.py:227](../../src/angerona/gui/storage_controls.py#L227) |
| Delete recovery copies… | QPushButton | `StorageControls.__init__` | `self._delete` · [src/angerona/gui/storage_controls.py:228](../../src/angerona/gui/storage_controls.py#L228) |

## Suite map

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Animate observed flow | QCheckBox | `SuiteMapDialog.__init__` | `self._animate` · [src/angerona/gui/suite_map.py:276](../../src/angerona/gui/suite_map.py#L276) |
| Reset view | QPushButton | `SuiteMapDialog.__init__` | `self.canvas.reset_view` · [src/angerona/gui/suite_map.py:279](../../src/angerona/gui/suite_map.py#L279) |
| Take me there | QPushButton | `SuiteMapDialog.__init__` | `self._navigate` · [src/angerona/gui/suite_map.py:296](../../src/angerona/gui/suite_map.py#L296) |

## Telemetry storage controls

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Block new telemetry event storage | QCheckBox | `TelemetryStorageControls.__init__` | [src/angerona/gui/telemetry_storage_controls.py:129](../../src/angerona/gui/telemetry_storage_controls.py#L129) |
| Generated label or icon | QToolButton | `TelemetryStorageControls.__init__` | `panel.setVisible`, `lambda enabled: toggle.setArrowType(Qt.DownArrow if enabled else Qt.RightArrow)` · [src/angerona/gui/telemetry_storage_controls.py:132](../../src/angerona/gui/telemetry_storage_controls.py#L132) |
| Block for this run | QPushButton | `TelemetryStorageControls.__init__` | [src/angerona/gui/telemetry_storage_controls.py:160](../../src/angerona/gui/telemetry_storage_controls.py#L160) |
| Allow within targets | QPushButton | `TelemetryStorageControls.__init__` | [src/angerona/gui/telemetry_storage_controls.py:161](../../src/angerona/gui/telemetry_storage_controls.py#L161) |
| Apply now / retry | QPushButton | `TelemetryStorageControls.__init__` | [src/angerona/gui/telemetry_storage_controls.py:162](../../src/angerona/gui/telemetry_storage_controls.py#L162) |
| Review oversized pending event… | QPushButton | `TelemetryStorageControls.__init__` | `self._review_unit` · [src/angerona/gui/telemetry_storage_controls.py:179](../../src/angerona/gui/telemetry_storage_controls.py#L179) |

## Threat intel page

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| 🔎  Analyze Fixes (AI) | QPushButton | `ThreatIntelDashboard.__init__` | `self._analyze_all` · [src/angerona/gui/threat_intel_page.py:283](../../src/angerona/gui/threat_intel_page.py#L283) |
| ⓘ  Why no bulk ignore? | QPushButton | `ThreatIntelDashboard.__init__` | `self._mass_flag_ignore` · [src/angerona/gui/threat_intel_page.py:292](../../src/angerona/gui/threat_intel_page.py#L292) |
| 🔍  Deep Analysis | QPushButton | `ThreatIntelDashboard.__init__` | `self._open_deep_analysis` · [src/angerona/gui/threat_intel_page.py:301](../../src/angerona/gui/threat_intel_page.py#L301) |
| 🌐  Consult AI | QPushButton | `ThreatIntelDashboard.__init__` | `self._open_consult_ai` · [src/angerona/gui/threat_intel_page.py:309](../../src/angerona/gui/threat_intel_page.py#L309) |
| ↺  Refresh | QPushButton | `ThreatIntelDashboard.__init__` | `self._load_and_render` · [src/angerona/gui/threat_intel_page.py:317](../../src/angerona/gui/threat_intel_page.py#L317) |
| 📋  Staged | QPushButton | `ThreatIntelDashboard.__init__` | `self._show_staged` · [src/angerona/gui/threat_intel_page.py:321](../../src/angerona/gui/threat_intel_page.py#L321) |
| Generated label or icon | QPushButton | `ThreatIntelDashboard._mini_btn` | `slot` · [src/angerona/gui/threat_intel_page.py:528](../../src/angerona/gui/threat_intel_page.py#L528) |
| Close | QPushButton | `ThreatIntelDashboard._show_history` | `dlg.close` · [src/angerona/gui/threat_intel_page.py:581](../../src/angerona/gui/threat_intel_page.py#L581) |
| 📋  Confirm & Stage proposal | QPushButton | `ThreatIntelDashboard._apply_fix` | `_run` · [src/angerona/gui/threat_intel_page.py:1065](../../src/angerona/gui/threat_intel_page.py#L1065) |
| Cancel | QPushButton | `ThreatIntelDashboard._apply_fix` | `dlg.reject` · [src/angerona/gui/threat_intel_page.py:1068](../../src/angerona/gui/threat_intel_page.py#L1068) |
| Generated label or icon | QPushButton | `ThreatIntelDashboard._stage_review` | `_toggle` · [src/angerona/gui/threat_intel_page.py:1190](../../src/angerona/gui/threat_intel_page.py#L1190) |
| 🕑 History | QPushButton | `ThreatIntelDashboard._stage_review` | `lambda: self._show_history(cve)` · [src/angerona/gui/threat_intel_page.py:1197](../../src/angerona/gui/threat_intel_page.py#L1197) |
| 🔎 Analyze fix | QPushButton | `ThreatIntelDashboard._stage_review` | `_do_analyze` · [src/angerona/gui/threat_intel_page.py:1209](../../src/angerona/gui/threat_intel_page.py#L1209) |
| 📋 Stage proposal | QPushButton | `ThreatIntelDashboard._stage_review` | `lambda: (self._apply_fix(cve, self._cached_analysis(cve, rec) or {}), dlg.accept())` · [src/angerona/gui/threat_intel_page.py:1210](../../src/angerona/gui/threat_intel_page.py#L1210) |
| ↩ Stage rollback | QPushButton | `ThreatIntelDashboard._stage_review` | `lambda: (self._revert_fix(cve), dlg.accept())` · [src/angerona/gui/threat_intel_page.py:1211](../../src/angerona/gui/threat_intel_page.py#L1211) |
| 🚫 Mark not applicable | QPushButton | `ThreatIntelDashboard._stage_review` | `_mark_not_applicable` · [src/angerona/gui/threat_intel_page.py:1212](../../src/angerona/gui/threat_intel_page.py#L1212) |
| NVD detail | QPushButton | `ThreatIntelDashboard._stage_review` | `lambda: _open(f'https://nvd.nist.gov/vuln/detail/{quote_plus(cve)}')` · [src/angerona/gui/threat_intel_page.py:1276](../../src/angerona/gui/threat_intel_page.py#L1276) |
| CISA KEV entry | QPushButton | `ThreatIntelDashboard._stage_review` | `lambda: _open('https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=' + quote_plus(cve))` · [src/angerona/gui/threat_intel_page.py:1278](../../src/angerona/gui/threat_intel_page.py#L1278) |
| Vendor advisory | QPushButton | `ThreatIntelDashboard._stage_review` | `lambda: _open('https://www.google.com/search?q=' + quote_plus(f'{cve} {vendor} {prod} security advisory patch'))` · [src/angerona/gui/threat_intel_page.py:1282](../../src/angerona/gui/threat_intel_page.py#L1282) |
| Confirm & Stage | QPushButton | `ThreatIntelDashboard._stage_review` | `_confirm` · [src/angerona/gui/threat_intel_page.py:1290](../../src/angerona/gui/threat_intel_page.py#L1290) |
| Close | QPushButton | `ThreatIntelDashboard._stage_review` | `dlg.close` · [src/angerona/gui/threat_intel_page.py:1291](../../src/angerona/gui/threat_intel_page.py#L1291) |
| Close | QPushButton | `ThreatIntelDashboard._show_staged` | `dlg.close` · [src/angerona/gui/threat_intel_page.py:1329](../../src/angerona/gui/threat_intel_page.py#L1329) |

## Top talkers

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Resolve hostnames: off | QPushButton | `TopTalkersDialog.__init__` | `lambda on: self._resolve_chk.setText(f"Resolve hostnames: {('on' if on else 'off')}")` · [src/angerona/gui/top_talkers.py:256](../../src/angerona/gui/top_talkers.py#L256) |
| Refresh now | QPushButton | `TopTalkersDialog.__init__` | `lambda: self.refresh(user_requested=True)` · [src/angerona/gui/top_talkers.py:262](../../src/angerona/gui/top_talkers.py#L262) |
| Close | QPushButton | `TopTalkersDialog.__init__` | `self.close` · [src/angerona/gui/top_talkers.py:264](../../src/angerona/gui/top_talkers.py#L264) |
| ✓ Mark reviewed | QPushButton | `TopTalkersDialog._process_actions` | `_allow` · [src/angerona/gui/top_talkers.py:395](../../src/angerona/gui/top_talkers.py#L395) |
| ⛔ Contain via Combat | QPushButton | `TopTalkersDialog._process_actions` | `_block` · [src/angerona/gui/top_talkers.py:396](../../src/angerona/gui/top_talkers.py#L396) |
| Close | QPushButton | `TopTalkersDialog._process_actions` | `dlg.close` · [src/angerona/gui/top_talkers.py:397](../../src/angerona/gui/top_talkers.py#L397) |
| 🤖 Ask AI | QPushButton | `TopTalkersDialog._process_actions` | `_ai` · [src/angerona/gui/top_talkers.py:397](../../src/angerona/gui/top_talkers.py#L397) |

## Tour

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Skip tour | QPushButton | `CoachMarks.__init__` | `self.close` · [src/angerona/gui/tour.py:127](../../src/angerona/gui/tour.py#L127) |
| Next → | QPushButton | `CoachMarks.__init__` | `self._advance` · [src/angerona/gui/tour.py:128](../../src/angerona/gui/tour.py#L128) |

## Ugcap page

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Open vault… | QPushButton | `UGCAPPage._build_vault_tab` | `self._choose_existing_vault` · [src/angerona/gui/ugcap_page.py:122](../../src/angerona/gui/ugcap_page.py#L122) |
| New vault path… | QPushButton | `UGCAPPage._build_vault_tab` | `self._choose_new_vault` · [src/angerona/gui/ugcap_page.py:125](../../src/angerona/gui/ugcap_page.py#L125) |
| Verify now | QPushButton | `UGCAPPage._build_vault_tab` | `self._verify` · [src/angerona/gui/ugcap_page.py:136](../../src/angerona/gui/ugcap_page.py#L136) |
| Initialize baseline | QPushButton | `UGCAPPage._build_vault_tab` | `self._initialize` · [src/angerona/gui/ugcap_page.py:139](../../src/angerona/gui/ugcap_page.py#L139) |
| Lock workspace | QPushButton | `UGCAPPage._build_vault_tab` | `self._lock` · [src/angerona/gui/ugcap_page.py:143](../../src/angerona/gui/ugcap_page.py#L143) |
| Restore selected reviewed paths | QPushButton | `UGCAPPage._build_vault_tab` | `self._restore` · [src/angerona/gui/ugcap_page.py:165](../../src/angerona/gui/ugcap_page.py#L165) |
| Vault / Review | Tab | `UGCAPPage._build_vault_tab` | [src/angerona/gui/ugcap_page.py:176](../../src/angerona/gui/ugcap_page.py#L176) |
| Enable UGCAP scheduled integrity challenges | QCheckBox | `UGCAPPage._build_settings_tab` | `self._mark_settings_dirty` · [src/angerona/gui/ugcap_page.py:181](../../src/angerona/gui/ugcap_page.py#L181) |
| Request local-host isolation when integrity divergence is detected | QCheckBox | `UGCAPPage._build_settings_tab` | `self._mark_settings_dirty` · [src/angerona/gui/ugcap_page.py:197](../../src/angerona/gui/ugcap_page.py#L197) |
| Apply UGCAP settings | QPushButton | `UGCAPPage._build_settings_tab` | `self._save_settings` · [src/angerona/gui/ugcap_page.py:204](../../src/angerona/gui/ugcap_page.py#L204) |
| Provision hardware TPM key | QPushButton | `UGCAPPage._build_settings_tab` | `self._provision_hardware` · [src/angerona/gui/ugcap_page.py:207](../../src/angerona/gui/ugcap_page.py#L207) |
| Schedule / Hardware | Tab | `UGCAPPage._build_settings_tab` | [src/angerona/gui/ugcap_page.py:221](../../src/angerona/gui/ugcap_page.py#L221) |
| Readiness / Results | Tab | `UGCAPPage._build_readiness_tab` | [src/angerona/gui/ugcap_page.py:232](../../src/angerona/gui/ugcap_page.py#L232) |
| How it works / Limits | Tab | `UGCAPPage._build_limits_tab` | [src/angerona/gui/ugcap_page.py:238](../../src/angerona/gui/ugcap_page.py#L238) |
| Require the separately enrolled UGCAP witness | QCheckBox | `UGCAPPage._build_witness_tab` | [src/angerona/gui/ugcap_page.py:249](../../src/angerona/gui/ugcap_page.py#L249) |
| Apply witness enrollment | QPushButton | `UGCAPPage._build_witness_tab` | `self._save_witness_settings` · [src/angerona/gui/ugcap_page.py:278](../../src/angerona/gui/ugcap_page.py#L278) |
| Provision / show host public key | QPushButton | `UGCAPPage._build_witness_tab` | `lambda: self._witness_command('queue_provision_witness_key')` · [src/angerona/gui/ugcap_page.py:281](../../src/angerona/gui/ugcap_page.py#L281) |
| Check witness now | QPushButton | `UGCAPPage._build_witness_tab` | `lambda: self._witness_command('queue_probe_witness')` · [src/angerona/gui/ugcap_page.py:284](../../src/angerona/gui/ugcap_page.py#L284) |
| Independent Witness | Tab | `UGCAPPage._build_witness_tab` | [src/angerona/gui/ugcap_page.py:307](../../src/angerona/gui/ugcap_page.py#L307) |

## Update controller

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Review current storage | QPushButton | `SourceUpdateStorageDialog.__init__` | `controller.review_storage` · [src/angerona/gui/update_controller.py:309](../../src/angerona/gui/update_controller.py#L309) |
| Export selected backup | QPushButton | `SourceUpdateStorageDialog.__init__` | `self._export_selected` · [src/angerona/gui/update_controller.py:310](../../src/angerona/gui/update_controller.py#L310) |
| Permanently delete selected backup | QPushButton | `SourceUpdateStorageDialog.__init__` | `self._delete_selected` · [src/angerona/gui/update_controller.py:311](../../src/angerona/gui/update_controller.py#L311) |
| Recheck prepared update | QPushButton | `SourceUpdateStorageDialog.__init__` | `controller.recheck_prepared_activation` · [src/angerona/gui/update_controller.py:318](../../src/angerona/gui/update_controller.py#L318) |
| Change retention limits | QPushButton | `SourceUpdateStorageDialog.__init__` | `self._save_policy` · [src/angerona/gui/update_controller.py:332](../../src/angerona/gui/update_controller.py#L332) |

## Upgrade console

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Open Settings > Mobile Integration | QPushButton | `AngeronaUpgradeConsole._init_mobile_tab` | `lambda: self._open_settings_tab('Mobile Integration')` · [src/angerona/gui/upgrade_console.py:250](../../src/angerona/gui/upgrade_console.py#L250) |
| Send confirmed test notification | QPushButton | `AngeronaUpgradeConsole._init_mobile_tab` | `self._test_mobile` · [src/angerona/gui/upgrade_console.py:254](../../src/angerona/gui/upgrade_console.py#L254) |
| Mobile Integration | Tab | `AngeronaUpgradeConsole._init_mobile_tab` | [src/angerona/gui/upgrade_console.py:261](../../src/angerona/gui/upgrade_console.py#L261) |
| Open Settings ▸ API Keys | QPushButton | `AngeronaUpgradeConsole._init_ai_sandbox_tab` | `self._open_api_key_settings` · [src/angerona/gui/upgrade_console.py:338](../../src/angerona/gui/upgrade_console.py#L338) |
| Install | QPushButton | `AngeronaUpgradeConsole._init_ai_sandbox_tab` | [src/angerona/gui/upgrade_console.py:371](../../src/angerona/gui/upgrade_console.py#L371) |
| Activate | QPushButton | `AngeronaUpgradeConsole._init_ai_sandbox_tab` | [src/angerona/gui/upgrade_console.py:372](../../src/angerona/gui/upgrade_console.py#L372) |
| Roll Back | QPushButton | `AngeronaUpgradeConsole._init_ai_sandbox_tab` | [src/angerona/gui/upgrade_console.py:373](../../src/angerona/gui/upgrade_console.py#L373) |
| Remove | QPushButton | `AngeronaUpgradeConsole._init_ai_sandbox_tab` | [src/angerona/gui/upgrade_console.py:374](../../src/angerona/gui/upgrade_console.py#L374) |
| Implement Code into a Sandbox File… | QPushButton | `AngeronaUpgradeConsole._init_ai_sandbox_tab` | `self._implement_code` · [src/angerona/gui/upgrade_console.py:394](../../src/angerona/gui/upgrade_console.py#L394) |
| AI Sandbox & Models | Tab | `AngeronaUpgradeConsole._init_ai_sandbox_tab` | [src/angerona/gui/upgrade_console.py:400](../../src/angerona/gui/upgrade_console.py#L400) |
| Watchdog Hub | Tab | `AngeronaUpgradeConsole._init_watchdog_tab` | [src/angerona/gui/upgrade_console.py:753](../../src/angerona/gui/upgrade_console.py#L753) |
| Telemetry Hub | Tab | `AngeronaUpgradeConsole._init_telemetry_tab` | [src/angerona/gui/upgrade_console.py:880](../../src/angerona/gui/upgrade_console.py#L880) |

## Usb approval dialog

| Control | Kind | Owning function | Handler or source |
| --- | --- | --- | --- |
| Keep blocked | QPushButton | `UsbApprovalDialog.__init__` | `self._deny` · [src/angerona/gui/usb_approval_dialog.py:130](../../src/angerona/gui/usb_approval_dialog.py#L130) |
| Generated label or icon | QPushButton | `UsbApprovalDialog.__init__` | `self._approve` · [src/angerona/gui/usb_approval_dialog.py:133](../../src/angerona/gui/usb_approval_dialog.py#L133) |
