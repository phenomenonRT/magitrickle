<script lang="ts">
  import Button from "./ui/Button.svelte";
  import GenericDialog from "./ui/GenericDialog.svelte";
  import { Check, MoveDown, MoveUp, SelectOpen } from "./ui/icons";
  import { interfaces, isKeeneticPolicyTarget } from "../data/interfaces.svelte";
  import { t } from "../data/locale.svelte";

  type Props = {
    selected?: string;
    fallbackInterfaces?: string[];
  };

  type TargetOption = {
    value: string;
    label: string;
    description?: string;
    unavailable?: boolean;
  };

  let {
    selected = $bindable<string>(""),
    fallbackInterfaces = $bindable<string[]>([]),
  }: Props = $props();

  let open = $state(false);
  let mode = $state<"policy" | "interfaces">("interfaces");
  let policyDraft = $state("");
  let channelDraft = $state<string[]>([]);

  const policyOptions = $derived(
    interfaces.list
      .filter((item) => item.kind === "policy")
      .map((item) => ({
        value: item.id,
        label: item.name?.trim() || item.id.replace("keenetic-policy:", ""),
        description: item.id.replace("keenetic-policy:", ""),
      })),
  );

  const interfaceOptions = $derived(
    interfaces.list
      .filter((item) => item.kind !== "policy" && !isKeeneticPolicyTarget(item.id))
      .map((item) => ({
        value: item.id,
        label: item.name?.trim() || item.id,
        description: item.name?.trim() && item.name.trim() !== item.id ? item.id : undefined,
      })),
  );

  const fallbackOptions = $derived(
    interfaceOptions.filter((option) => option.value !== "blackhole"),
  );

  const interfaceRows = $derived.by(() => {
    const byId = new Map<string, TargetOption>(
      interfaceOptions.map((option): [string, TargetOption] => [option.value, option]),
    );
    const selected = channelDraft.map(
      (id) =>
        byId.get(id) ?? {
          value: id,
          label: id,
          description: t("Interface unavailable"),
          unavailable: true,
        },
    );
    const displayed = new Set(channelDraft);
    return [
      ...selected,
      ...interfaceOptions.filter((option) => !displayed.has(option.value)),
    ];
  });

  const triggerLabel = $derived.by(() => {
    const policy = policyOptions.find((option) => option.value === selected);
    if (policy) return `${t("Keenetic policy")}: ${policy.label}`;

    const iface = interfaceOptions.find((option) => option.value === selected);
    return iface?.label ?? (selected || t("Choose connection"));
  });

  const selectedFallbackCount = $derived(
    isKeeneticPolicyTarget(selected)
      ? 0
      : fallbackInterfaces.filter((item) => item !== selected).length,
  );

  function beginEditing() {
    const usingPolicy = isKeeneticPolicyTarget(selected) && policyOptions.length > 0;
    mode = usingPolicy ? "policy" : "interfaces";
    policyDraft = usingPolicy
      ? selected
      : (policyOptions[0]?.value ?? "");
    if (usingPolicy) {
      channelDraft = [];
    } else if (selected === "blackhole") {
      channelDraft = [selected];
    } else {
      const configured = [selected, ...fallbackInterfaces].filter(
        (item) => Boolean(item) && item !== "blackhole",
      );
      channelDraft = [...new Set(configured)];
    }
    open = true;
  }

  function close() {
    open = false;
  }

  function save() {
    if (mode === "policy") {
      if (!policyDraft) return;
      selected = policyDraft;
      fallbackInterfaces = [];
    } else {
      const primary = channelDraft[0];
      if (!primary) return;
      selected = primary;
      fallbackInterfaces =
        primary === "blackhole"
          ? []
          : channelDraft.slice(1).filter((item) => item !== "blackhole");
    }
    close();
  }

  function toggleChannel(id: string, checked: boolean) {
    if (checked) {
      if (id === "blackhole") {
        channelDraft = [id];
      } else if (!channelDraft.includes(id)) {
        channelDraft = [...channelDraft.filter((item) => item !== "blackhole"), id];
      }
      return;
    }
    channelDraft = channelDraft.filter((item) => item !== id);
  }

  function selectAllChannels() {
    if (fallbackOptions.length === 0) return;

    const current = channelDraft.filter(
      (id) => id !== "blackhole" && interfaceOptions.some((option) => option.value === id),
    );
    channelDraft = [
      ...current,
      ...fallbackOptions.map((option) => option.value).filter((id) => !current.includes(id)),
    ];
  }

  function clearChannels() {
    channelDraft = [];
  }

  function moveChannel(id: string, offset: -1 | 1) {
    const index = channelDraft.indexOf(id);
    const target = index + offset;
    if (index < 0 || target < 0 || target >= channelDraft.length) return;

    const next = [...channelDraft];
    [next[index], next[target]] = [next[target], next[index]];
    channelDraft = next;
  }
</script>

<button
  type="button"
  class="connection-picker-trigger"
  onclick={beginEditing}
  aria-haspopup="dialog"
  aria-expanded={open}
>
  <span class="trigger-label">{triggerLabel}</span>
  {#if selectedFallbackCount > 0}
    <span class="fallback-count">+{selectedFallbackCount}</span>
  {/if}
  <span class="trigger-open" aria-hidden="true"><SelectOpen size={16} /></span>
</button>

<GenericDialog {open} title={t("Connection")} maxWidth={500} on:close={close}>
  <div slot="body" class="connection-picker">
    {#if policyOptions.length > 0}
      <div class="mode-tabs" role="tablist" aria-label={t("Connection mode")}>
        <button
          type="button"
          role="tab"
          aria-selected={mode === "policy"}
          class:active={mode === "policy"}
          onclick={() => (mode = "policy")}
        >
          {t("Keenetic policy")}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={mode === "interfaces"}
          class:active={mode === "interfaces"}
          onclick={() => (mode = "interfaces")}
        >
          {t("Interfaces")}
        </button>
      </div>
    {/if}

    {#if mode === "policy" && policyOptions.length > 0}
      <p class="hint">{t("Choose a Keenetic internet access policy. Failover is managed by Keenetic.")}</p>
      <div class="target-list">
        {#each policyOptions as option (option.value)}
          <button
            type="button"
            class="policy-option"
            class:selected={policyDraft === option.value}
            aria-pressed={policyDraft === option.value}
            onclick={() => (policyDraft = option.value)}
          >
            <span class="radio-mark"></span>
            <span class="target-info">
              <span class="target-name">{option.label}</span>
              <span class="target-meta">{option.description}</span>
            </span>
            {#if policyDraft === option.value}<Check size={18} />{/if}
          </button>
        {/each}
      </div>
    {:else}
      <p class="hint">{t("Select channels. The first selected is primary; the rest are fallbacks. Use arrows to set priority.")}</p>
      <div class="list-toolbar">
        <div class="bulk-actions">
          <Button type="button" small onclick={selectAllChannels}>{t("All")}</Button>
          <Button type="button" small onclick={clearChannels}>{t("Reset")}</Button>
        </div>
        <span class="selected-count">{t("Channels selected")}: {channelDraft.length}</span>
      </div>

      <div class="interface-list">
        {#each interfaceRows as option (option.value)}
          {@const channelIndex = channelDraft.indexOf(option.value)}
          <div
            class="interface-option"
            class:selected={channelIndex >= 0}
            class:unavailable={option.unavailable}
          >
            <label class="channel-checkbox">
              <input
                type="checkbox"
                checked={channelIndex >= 0}
                aria-label={t("Select interface") + ": " + option.label}
                onchange={(event) =>
                  toggleChannel(option.value, (event.currentTarget as HTMLInputElement).checked)}
              />
              <span class="channel-checkmark" aria-hidden="true">
                {#if channelIndex >= 0}<Check size={12} />{/if}
              </span>
            </label>

            <span class="target-info">
              <span class="target-name">{option.label}</span>
              {#if channelIndex === 0}
                <span class="channel-role">{t("Primary")}</span>
              {:else if channelIndex > 0}
                <span class="channel-role">{t("Fallback")}</span>
              {/if}
              {#if option.description}
                <span class="target-meta">{option.description}</span>
              {/if}
            </span>

            {#if channelIndex >= 0}
              <span class="priority-actions">
                <span class="priority">{channelIndex + 1}</span>
                <Button
                  small
                  type="button"
                  disabled={channelIndex === 0}
                  aria-label={t("Move Up")}
                  onclick={() => moveChannel(option.value, -1)}
                ><MoveUp size={16} /></Button>
                <Button
                  small
                  type="button"
                  disabled={channelIndex === channelDraft.length - 1}
                  aria-label={t("Move Down")}
                  onclick={() => moveChannel(option.value, 1)}
                ><MoveDown size={16} /></Button>
              </span>
            {:else}
              <span class="priority-actions-placeholder"></span>
            {/if}
          </div>
        {/each}
        {#if interfaceOptions.length === 0}
          <div class="empty-state">{t("No network interfaces available")}</div>
        {/if}
      </div>
    {/if}
  </div>

  <div slot="actions" class="dialog-actions">
    <Button type="button" onclick={close}>{t("Cancel")}</Button>
    <Button
      type="button"
      disabled={mode === "policy" ? !policyDraft : channelDraft.length === 0}
      onclick={save}
    >{t("Save Changes")}</Button>
  </div>
</GenericDialog>

<style>
  .connection-picker-trigger {
    display: inline-flex;
    align-items: center;
    justify-content: flex-start;
    gap: 0.3rem;
    max-width: 100%;
    min-width: 0;
    height: fit-content;
    padding: 0.2rem 0.3rem;
    border: none;
    border-radius: 0.5rem;
    background: transparent;
    color: var(--text);
    font: 400 1rem var(--font);
    line-height: 1.05;
    text-align: left;
    cursor: pointer;
  }

  .connection-picker-trigger:focus-visible {
    outline: none;
    background: var(--bg-light-extra);
  }

  .trigger-label {
    max-width: 18rem;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .fallback-count {
    flex-shrink: 0;
    color: var(--text-2);
    font-size: 0.78em;
  }

  .trigger-open {
    width: 16px;
    height: 16px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    color: var(--text-2);
    transition: transform 0.16s ease;
  }

  .connection-picker-trigger[aria-expanded="true"] .trigger-open {
    transform: rotate(180deg);
  }

  .connection-picker {
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
    padding-top: 0.15rem;
  }

  .mode-tabs {
    display: flex;
    gap: 0.25rem;
    padding: 0.2rem;
    border-radius: 0.55rem;
    background: var(--bg-light);
  }

  .mode-tabs button {
    flex: 1;
    border: 1px solid transparent;
    border-radius: 0.4rem;
    padding: 0.55rem 0.65rem;
    background: transparent;
    color: var(--text-2);
    font: inherit;
    cursor: pointer;
  }

  .mode-tabs button.active {
    background: var(--bg-dark);
    border-color: var(--bg-light-extra);
    color: var(--text);
  }

  .hint {
    margin: 0;
    color: var(--text-2);
    font-size: 0.9rem;
    line-height: 1.4;
  }

  .list-toolbar,
  .bulk-actions,
  .dialog-actions {
    display: flex;
    align-items: center;
  }

  .list-toolbar {
    justify-content: space-between;
    gap: 0.5rem;
  }

  .bulk-actions {
    gap: 0.35rem;
  }

  .selected-count {
    color: var(--text-2);
    font-size: 0.85rem;
    font-variant-numeric: tabular-nums;
  }

  .target-list,
  .interface-list {
    max-height: min(300px, 45vh);
    overflow: auto;
    display: flex;
    flex-direction: column;
    margin: 0 -1rem;
    padding: 0.25rem 1rem;
    scrollbar-gutter: stable;
  }

  .policy-option {
    min-height: 3rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.45rem 0.55rem;
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.45rem;
    background: var(--bg-light);
    color: var(--text);
    text-align: left;
    cursor: pointer;
  }

  .policy-option + .policy-option {
    margin-top: 0.35rem;
  }

  .policy-option.selected {
    background-color: var(--bg-medium);
    border-color: var(--bg-light-extra);
  }

  .radio-mark {
    width: 1rem;
    height: 1rem;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: 0 0 auto;
    border: 1.5px solid var(--bg-light-extra);
    border-radius: 50%;
    background: var(--bg-dark);
  }

  .policy-option.selected .radio-mark {
    border-color: var(--text-2);
  }

  .policy-option.selected .radio-mark::after {
    content: "";
    width: 0.48rem;
    height: 0.48rem;
    border-radius: 50%;
    background: var(--text-2);
  }

  .target-info {
    min-width: 0;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    flex: 1;
  }

  .target-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text);
  }

  .target-meta {
    flex-shrink: 0;
    color: var(--text-2);
    font-size: 0.78rem;
  }

  .interface-option {
    display: grid;
    grid-template-columns: 2rem minmax(0, 1fr) auto;
    align-items: center;
    gap: 0.4rem;
    min-height: 2.65rem;
    padding: 0.3rem 0.1rem;
    border-bottom: 1px solid var(--bg-light-extra);
  }

  .interface-option.selected {
    background-color: var(--bg-medium);
  }

  .interface-option.unavailable {
    opacity: 0.65;
  }

  .interface-option .target-info {
    justify-content: flex-start;
    gap: 0.55rem;
  }

  .interface-option .target-meta {
    margin-left: auto;
  }

  .channel-role {
    flex-shrink: 0;
    color: var(--text-2);
    font-size: 0.7rem;
  }

  .channel-checkbox {
    position: relative;
    width: 20px;
    height: 20px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    cursor: pointer;
  }

  .channel-checkbox input {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    margin: 0;
    opacity: 0;
    cursor: inherit;
  }

  .channel-checkmark {
    box-sizing: border-box;
    width: 100%;
    height: 100%;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: 1.5px solid var(--bg-light-extra);
    border-radius: 0.4rem;
    background: var(--bg-dark);
    color: var(--bg-dark);
    transition: background-color 0.12s ease, border-color 0.12s ease;
  }

  .channel-checkbox:hover .channel-checkmark {
    border-color: var(--text-2);
  }

  .channel-checkbox input:checked + .channel-checkmark {
    border-color: var(--accent);
    background: var(--accent);
  }

  .channel-checkbox input:focus-visible + .channel-checkmark {
    outline: 2px solid var(--accent);
    outline-offset: 3px;
  }

  .priority-actions {
    display: flex;
    align-items: center;
    gap: 0.1rem;
  }

  .priority-actions :global(button) {
    padding: 0.2rem;
  }

  .priority {
    width: 1rem;
    color: var(--text-2);
    font-size: 0.78rem;
    text-align: center;
    font-variant-numeric: tabular-nums;
  }

  .priority-actions-placeholder {
    width: 4.5rem;
  }

  .empty-state {
    padding: 1.25rem 0.5rem;
    color: var(--text-2);
    text-align: center;
  }

  .dialog-actions {
    justify-content: flex-end;
    gap: 0.5rem;
  }

  @media (max-width: 460px) {
    .target-meta {
      max-width: 30vw;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .priority-actions-placeholder {
      width: 2rem;
    }
  }
</style>
